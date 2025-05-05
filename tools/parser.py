from datetime import datetime
import io
import json
import re
from typing import Dict, List, Optional
from fastapi import HTTPException
from schemas.rowDTO import RowDTO
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

import re
from typing import List
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

def parse_apache_log(contents: str) -> List[RowDTO]:
    rows = []

    # Regex principal (supporte les logs Apache classiques et variantes)
    log_pattern = (
        r'(?P<ip>\S+) (?P<remote_logname>\S+) (?P<user>\S+) \[(?P<timestamp>.*?)\] '
        r'"(?P<method>\S+) (?P<url>\S+)(?: HTTP/(?P<protocol_version>\S+))?" (?P<status_code>\d+) '
        r'(?P<response_size>-|\d+)(?: "(?P<referrer>.*?)" "(?P<user_agent>.*?)")?'
    )

    for line in contents.splitlines():
        match = re.match(log_pattern, line)
        
        if match:
            log_data = match.groupdict()

            status_code = int(log_data['status_code']) if log_data['status_code'].isdigit() else 0
            response_size = int(log_data['response_size']) if log_data['response_size'].isdigit() else 0
            protocol_version = log_data.get('protocol_version', None)
            protocol = f"HTTP/{protocol_version}" if protocol_version else "unknown"

            try:
                row_dto = RowDTO(
                    ip=log_data['ip'],
                    timestamp=log_data['timestamp'],
                    method=log_data['method'],
                    url=log_data['url'],
                    status=status_code,
                    response_size=response_size,
                    referer=log_data.get('referrer', '-'),
                    user_agent=log_data.get('user_agent', '-'),
                    remote_logname=log_data['remote_logname'],
                    user=log_data['user'],
                    protocol=protocol
                )
                rows.append(row_dto)
                logger.info(f"Parsed log line successfully: {line}")
            except Exception as e:
                logger.warning(f"Skipping invalid log line due to error: {e} | Line: {line}")
        else:
            logger.warning(f"Skipping unparsable log line: {line}")

    if not rows:
        raise HTTPException(status_code=400, detail="No valid log entries found in the file.")

    return rows


APACHE_ERROR_LOG_PATTERN = re.compile(
    r'^\[(?P<timestamp>.*?)\] '
    r'\[(?P<module>\w+):(?P<level>\w+)\] '  # Extracts module and log level separately
    r'(?:\[pid (?P<pid>\d+):tid (?P<tid>\d+)\] )?'  # Optional PID and TID
    r'(?:\[client (?P<ip>\S+):\d+\] )?'  # Optional client IP
    r'(?P<message>.*?)$'  # Error message
)


def parse_apache_error_log(contents: str) -> List[RowDTO]:
    rows = []
    
    for line in contents.splitlines():
        match = APACHE_ERROR_LOG_PATTERN.match(line)
        
        if match:
            log_data = match.groupdict()
            
            row_dto = RowDTO(
                ip=log_data.get('ip', 'N/A'),
                timestamp=log_data.get('timestamp', 'Unknown Timestamp'),
                message=log_data.get('message', 'No message provided'),
                module = log_data.get('module', 'UNKNOWN').lower(),
                level=log_data.get('level', 'UNKNOWN').lower(),
                component="Apache",
                pid = log_data.get('pid', 'N/A'),
                tid = log_data.get('tid','N/A')
            )
            rows.append(row_dto)
        else:
            logger.warning(f"Skipping unparsable log line: {line}")
    
    return rows  # Return an empty list instead of raising an exception

def parse_nginx_log(contents: str) -> List[RowDTO]:
    rows = []
    
    # Regex pattern for the default NGINX combined log format
    log_pattern = (r'(?P<ip>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>.*?)\] '
                   r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>HTTP/\S+)" (?P<status_code>\d+) '
                   r'(?P<response_size>(\d+|-)) "(?P<referer>.*?)" "(?P<user_agent>.*?)"')

    for line in contents.splitlines():
        match = re.match(log_pattern, line)
        
        if match:
            log_data = match.groupdict()
            
            # Handle status code properly, defaulting to 0 if not found
            if 'status_code' in log_data and log_data['status_code']:
                logger.debug(f"status_code: {log_data['status_code']}")
                status_code = int(log_data['status_code'])
            else:
                status_code = 0  # Default value if status code is not found
            
            # Handle response size, defaulting to 0 if it is "-"
            response_size = int(log_data['response_size']) if log_data['response_size'] != "-" else 0
            
            try:
                # Creating RowDTO object with all the necessary fields
                row_dto = RowDTO(
                    ip=log_data['ip'],
                    timestamp=log_data['timestamp'],
                    method=log_data['method'],
                    url=log_data['url'],
                    status=status_code,
                    response_size=response_size,
                    referer=log_data['referer'],
                    user_agent=log_data['user_agent'],
                    protocol=log_data['protocol'],
                    remote_logname=log_data['remote_user']
                )
                rows.append(row_dto)
            except Exception as e:
                logger.warning(f"Skipping invalid log line: {line} due to error: {e}")
        else:
            logger.warning(f"Skipping unparsable log line: {line}")
    
    if not rows:
        raise HTTPException(status_code=400, detail="No valid log entries found in the file.")
    
    return rows

def parse_nginx_error_log(contents: str) -> List[RowDTO]:
    rows = []

    # Updated regex pattern with optional groups
    log_pattern = re.compile(
        r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
        r'\[(?P<log_level>\w+)\] '
        r'(?P<pid>\d+): '
        r'(?:\*?\d+ )?'  # Some logs may have "*1234"
        r'(?:client: (?P<client_ip>\d+\.\d+\.\d+\.\d+), )?'  # Optional client IP
        r'(?:server: (?P<server>\S+), )?'  # Optional server
        r'(?:request: "(?P<request>.*?)", )?'  # Optional request
        r'(?:host: "(?P<host>.*?)", )?'  # Optional host
        r'(?P<message>.+)'  # Main log message
    )

    for line in contents.splitlines():
        match = log_pattern.match(line)

        if match:
            log_data = match.groupdict()

            try:
                row_dto = RowDTO(
                    timestamp=log_data['timestamp'],
                    level=log_data['log_level'],
                    pid=log_data['pid'],
                    ip=log_data.get('client_ip', 'N/A'),
                    message=log_data['message'],
                    request=log_data.get('request'),
                    host=log_data.get('host'),
                    server=log_data.get('server')
                )
                rows.append(row_dto)
            except Exception as e:
                logger.warning(f"Skipping invalid log line: {line} due to error: {e}")
        else:
            logger.warning(f"Skipping unparsable log line: {line}")

    if not rows:
        raise Exception("No valid log entries found in the file.")

    return rows

def parse_time_generated(time_str: str) -> str:
    # Assuming time is in Unix timestamp format
    try:
        timestamp = datetime.utcfromtimestamp(int(time_str[6:-2])/1000)
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Error parsing time: {e}")
        return ""

def parse_message(message: str) -> tuple:
    # This function should be designed to extract information from the message string
    # Placeholder to extract some key details from the message
    security_id = account_name = logon_id = None
    try:
        # For example: extracting security_id, account_name, logon_id from the message
        if "Security ID" in message:
            security_id = message.split("Security ID:")[1].split("\r\n")[0].strip()
        if "Account Name" in message:
            account_name = message.split("Account Name:")[1].split("\r\n")[0].strip()
        if "Logon ID" in message:
            logon_id = message.split("Logon ID:")[1].split("\r\n")[0].strip()
    except Exception as e:
        print(f"Error parsing message: {e}")
    return security_id, account_name, logon_id


async def parse_windows_security_log(contents: str) -> List[RowDTO]:
    try:
        logs = json.loads(contents)  # Assuming the contents is a JSON string (can be a JSON array)
        rows = []
        
        for log in logs:
            time_generated = parse_time_generated(log["TimeCreated"]) if log.get("TimeCreated") else ""
            entry_type = log.get("EntryType")
            provider_name = log.get("ProviderName")
            instance_id = log.get("Id")
            message = log.get("Message")
            computer_name = log.get("ComputerName")
            task_display_name = log.get("TaskDisplayName")
            level_display_name = log.get("LevelDisplayName")
            user_name = log.get("UserName")
            run_as_user = log.get("RunAsUser")
            
            # Parse additional details from the message
            security_id, account_name, logon_id = parse_message(message)
            
            # Create RowDTO for each log entry
            row_dto = RowDTO(
                timestamp=time_generated,
                message=message,
                event_id=instance_id,
                entry_type=entry_type,
                provider_name=provider_name,
                computer_name=computer_name,
                task_display_name=task_display_name,
                level_display_name=level_display_name,
                user_name=user_name,
                run_as_user=run_as_user,
                account_name=account_name,  # Optional, can use account_name from parsed message
                # You can populate other fields based on available data here
            )
            
            rows.append(row_dto)
        
        return rows
    except Exception as e:
        print(f"Error parsing Windows security log: {e}")
        raise HTTPException(status_code=400, detail="Error parsing Windows security log.")
    
async def parse_syslog(contents: str) -> List[RowDTO]:
    rows = []
    
    log_pattern = (
        r'(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{6})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s+'
        r'(?P<message>.*)'
    )

    ssh_pattern = (
        r'(?P<action>Accepted|Failed)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+'
        r'from\s+(?P<ip>\S+)\s+port\s+\d+\s+ssh2'
    )

    for line in contents.splitlines():
        match = re.match(log_pattern, line)
        
        if match:
            log_data = match.groupdict()
            
            try:
                row_dto = RowDTO(
                    timestamp=convert_syslog_timestamp(log_data['timestamp']),
                    hostname=log_data['hostname'],
                    module=log_data['service'],
                    pid=log_data['pid'] if log_data['pid'] else '0',
                    message=log_data['message'],
                    ip=None,
                    user=None
                )

                ssh_match = re.search(ssh_pattern, log_data['message'])
                if ssh_match:
                    ssh_data = ssh_match.groupdict()
                    row_dto.ip = ssh_data['ip']
                    row_dto.user = ssh_data['user']

                rows.append(row_dto)
            except Exception as e:
                logger.warning(f"Skipping invalid log line: {line} due to error: {e}")
        else:
            logger.warning(f"Skipping unparsable log line: {line}")
    
    if not rows:
        raise HTTPException(status_code=400, detail="No valid log entries found in the file.")
    
    return rows

def convert_syslog_timestamp(syslog_time: str, current_year: int = None) -> str:
    try:
        months = {
            "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
            "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
            "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"
        }
        
        if current_year is None:
            current_year = datetime.now().year
        
        parts = syslog_time.split()
        month_str, day, time_str = parts[0], parts[1], parts[2]
        
        month_num = months[month_str]
        
        formatted_time = f"{int(day)}/{month_str}/{current_year}:{time_str[:2]}:{time_str[2:4]}:{time_str[4:]}"
        return formatted_time
    except:
        return syslog_time

def fix_regex_pattern(pattern: str) -> Optional[str]:
    """
    Attempts to fix a broken regex pattern by applying common repairs and validating the result.
    
    Args:
        pattern (str): The potentially broken regex pattern to fix.
    
    Returns:
        Optional[str]: The fixed regex pattern if successful, None if unfixable.
    """
    if not pattern:
        logger.error("Empty regex pattern provided.")
        return None

    original_pattern = pattern

    def try_compile(test_pattern: str) -> bool:
        try:
            re.compile(test_pattern)
            return True
        except re.error:
            return False

    if try_compile(pattern):
        logger.info(f"Original pattern is valid: {pattern}")
        return pattern

    fixed_pattern = pattern

    problematic_chars = r"([.+*?{}()[\]^$\\|])"
    if not all(c.isalnum() or c.isspace() or c in "():?P<>" for c in fixed_pattern):
        fixed_pattern = re.sub(r"(?<!\\)" + problematic_chars, r"\\\1", fixed_pattern)
        logger.debug(f"After escaping problematic chars: {fixed_pattern}")
        if try_compile(fixed_pattern):
            logger.info(f"Fixed by escaping characters: {fixed_pattern}")
            return fixed_pattern

    open_parens = fixed_pattern.count("(") - fixed_pattern.count(r"\(")
    close_parens = fixed_pattern.count(")") - fixed_pattern.count(r"\)")
    if open_parens > close_parens:
        fixed_pattern += ")" * (open_parens - close_parens)
        logger.debug(f"Added closing parens: {fixed_pattern}")
    elif close_parens > open_parens:
        fixed_pattern = "(" * (close_parens - open_parens) + fixed_pattern
        logger.debug(f"Added opening parens: {fixed_pattern}")
    if try_compile(fixed_pattern):
        logger.info(f"Fixed by balancing parentheses: {fixed_pattern}")
        return fixed_pattern

    if fixed_pattern.endswith("\\"):
        fixed_pattern = fixed_pattern.rstrip("\\")
        logger.debug(f"Removed trailing backslash: {fixed_pattern}")
        if try_compile(fixed_pattern):
            logger.info(f"Fixed by removing trailing backslash: {fixed_pattern}")
            return fixed_pattern

    named_group_pattern = r"\(\?P<([^>]+)>[^)]+\)"
    groups = re.findall(named_group_pattern, fixed_pattern)
    for group_name in groups:
        if not group_name.isidentifier():
            logger.debug(f"Invalid group name '{group_name}', replacing with valid name.")
            fixed_pattern = fixed_pattern.replace(f"(?P<{group_name}>", f"(?P<group_{groups.index(group_name)}>")
    if try_compile(fixed_pattern):
        logger.info(f"Fixed by correcting named groups: {fixed_pattern}")
        return fixed_pattern

    if fixed_pattern.endswith(("+", "*", "?")):
        fixed_pattern += ".*"
        logger.debug(f"Terminated dangling quantifier: {fixed_pattern}")
        if try_compile(fixed_pattern):
            logger.info(f"Fixed by terminating quantifier: {fixed_pattern}")
            return fixed_pattern

    try:
        parts = re.split(r"(\\[.*?\\]|\(.*?[^\)]\)|[^\[\(]+)", fixed_pattern)
        working_pattern = ""
        for part in parts:
            if part:
                test_pattern = working_pattern + part
                if try_compile(test_pattern):
                    working_pattern = test_pattern
                else:
                    logger.debug(f"Skipped problematic part: {part}")
        if try_compile(working_pattern) and working_pattern:
            logger.info(f"Fixed by rebuilding pattern: {working_pattern}")
            return working_pattern
    except Exception as e:
        logger.debug(f"Rebuild attempt failed: {str(e)}")

    logger.error(f"Unable to fix regex pattern. Original: {original_pattern}, Final attempt: {fixed_pattern}")
    return None

def parse_log_file(file: str, log_pattern: str) -> List[RowDTO]:
    """
    Parse a log file using a provided regex pattern and return a list of dictionaries
    with named capture groups. Attempts to fix the regex if it's invalid.
    
    Args:
        file (str): The log file content as a string.
        log_pattern (str): The regex pattern with named capture groups to parse the logs.
    
    Returns:
        List[Dict[str, str]]: A list of dictionaries, each containing the matched groups for a log line.
    
    Raises:
        HTTPException: If the regex is invalid and unfixable, no valid entries are parsed, or processing fails.
    """
    # Attempt to compile the original pattern
    compiled_pattern = None
    try:
        compiled_pattern = re.compile(log_pattern)
        logger.info(f"Original regex pattern compiled successfully: {log_pattern}")
    except re.error as e:
        logger.warning(f"Invalid regex pattern: {str(e)}. Attempting to fix.")
        
        # Try to fix the pattern
        fixed_pattern = fix_regex_pattern(log_pattern)
        if fixed_pattern:
            try:
                compiled_pattern = re.compile(fixed_pattern)
                logger.info(f"Successfully fixed and compiled regex pattern: {fixed_pattern}")
            except re.error as e:
                logger.error(f"Fixed pattern still invalid: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Regex pattern remains invalid after attempted fix: {str(e)}")
        else:
            logger.error("Could not fix the invalid regex pattern.")
            raise HTTPException(status_code=500, detail=f"Invalid regex pattern and unable to fix: {str(e)}")

    rows = []
    unparsed_count = 0

    try:
        # Split the file into lines if it's a string
        if isinstance(file, str):
            lines = file.splitlines()
        else:
            lines = file  # Assume it's already an iterable of lines

        for line in lines:
            if not line.strip():  # Skip empty lines
                continue
            
            # Attempt to match the line with the compiled regex
            match = compiled_pattern.match(line.strip())
            if match:
                # Extract all named capture groups into a dictionary
                log_data = match.groupdict()
                # Replace empty strings with None for consistency
                log_data = {k: (v if v else None) for k, v in log_data.items()}
                rows.append(log_data)
                logger.info(f"Parsed log line successfully: {line.strip()}")
            else:
                unparsed_count += 1
                logger.warning(f"Skipping unparsable log line: {line.strip()}")

    except Exception as e:
        logger.exception(f"Error processing log data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing log data: {str(e)}")

    if not rows:
        logger.error(f"No valid log entries found. {unparsed_count} lines skipped.")
        raise HTTPException(
            status_code=400,
            detail=f"No valid log entries found. {unparsed_count} lines skipped."
        )

    if unparsed_count > 0:
        logger.info(f"Processed log data with {len(rows)} valid entries, {unparsed_count} lines skipped.")

    rowsD = [RowDTO(**row) for row in rows]
    return rowsD