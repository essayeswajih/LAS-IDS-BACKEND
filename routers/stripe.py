from logging import getLogger
import os
from dotenv import load_dotenv
from requests import Session
import stripe
from fastapi import APIRouter, Depends, HTTPException, status
from starlette.config import Config
from fastapi.responses import JSONResponse

from db.database import get_db
from models.usersEntity import RoleEnum, User
from routers.auth import get_current_user

router = APIRouter(tags = ["stripe"])
logger = getLogger(__name__)
load_dotenv()

stripe.api_key = os.getenv("STRIPE_API_KEY") 

@router.post("/create-checkout-session")
def create_checkout_session(
    user_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Validate environment variables
        if not stripe.api_key:
            logger.error("Stripe API key is not set.")
            raise HTTPException(status_code=500, detail="Server configuration error: Stripe API key missing.")
        if not os.getenv("STRIPE_PRICE_ID"):
            logger.error("STRIPE_PRICE_ID is not set.")
            raise HTTPException(status_code=500, detail="Server configuration error: Stripe Price ID missing.")
        if not os.getenv("SUCCESS_URL") or not os.getenv("CANCEL_URL"):
            logger.error("SUCCESS_URL or CANCEL_URL is not set.")
            raise HTTPException(status_code=500, detail="Server configuration error: Success or Cancel URL missing.")

        # Get or update the user with their Stripe customer ID
        user = db.query(User).filter_by(id=user_data["id"]).first()
        if not user:
            logger.warning(f"User not found for ID: {user_data['id']}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")

        if not user.stripe_customer_id:
            logger.info(f"Creating Stripe customer for user {user.id}")
            customer = stripe.Customer.create(email=user.email)
            user.stripe_customer_id = customer.id
            logger.info(f"Stripe customer {customer.id} created and saved for user {user.id}")

        # Create a Checkout Session for a subscription
        logger.info(f"Creating checkout session for user {user.id} with customer ID {user.stripe_customer_id}")
        session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": "IDS Premium Access",
                        },
                        "unit_amount": 2000,  # $20 in cents
                    },
                    "quantity": 1,
                },
            ],
            mode="payment",  # One-time payment
            success_url=os.getenv("SUCCESS_URL") + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=os.getenv("CANCEL_URL"),
        )
        user.role = RoleEnum.pro
        db.commit()
        logger.info(f"Checkout session {session.id} created successfully")
        return JSONResponse({"id": session.id})

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/check-subscription")
def check_subscription(
    user_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter_by(id=user_data["id"]).first()
    if not user:
        logger.warning(f"User not found for ID: {user_data['id']}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed.")
    if not user.stripe_customer_id:
        return {"subscribed": False}

    try:
        # Check for successful one-time payments
        charges = stripe.Charge.list(
            customer=user.stripe_customer_id,
            status="succeeded"
        )
        return {"subscribed": len(charges.data) > 0}  
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))