from fastapi import FastAPI, Response, Request  # Import Request
import uvicorn
from routers.auth import router as authRouter
from routers.rowsController import router as rowsRouter
from routers.logsController import router as logsRouter
from routers.usersController import router as usersRouter
from routers.notificationController import router as notificationsRouter
from routers.report_controller import router as reportsRouter
from routers.ai import router as aiRouter
from routers.stripe import router as stripeRouter
from fastapi.middleware.cors import CORSMiddleware
from db.database import Base, engine
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

# Initialize the rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
# Base metadata setup
# Base.metadata.drop_all(bind=engine)
# Base metadata setup
Base.metadata.create_all(bind=engine)

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda request, exc: Response(content="Rate limit exceeded", status_code=429),
)
app.add_middleware(SlowAPIMiddleware)

# Include routers
app.include_router(rowsRouter, prefix="/api/v1",)
app.include_router(logsRouter, prefix="/api/v1")
app.include_router(authRouter)
app.include_router(usersRouter, prefix="/api/v1")
app.include_router(notificationsRouter, prefix="/api/v1")
app.include_router(aiRouter, prefix="/api/v1")
app.include_router(reportsRouter, prefix="/api/v1/reports")
app.include_router(stripeRouter, prefix="/api/v1/stripe")
# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust allowed origins as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
@limiter.limit("5/minute")
def read_root(request: Request): 
    return {"message": "API is working"}

@app.get("/favicon.ico", response_class=Response)
async def favicon():
    return Response(status_code=204)  # No Content

if __name__ == "__main__":
    uvicorn.run(app, port=8000)
