import os
import traceback
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from supabase import create_client, Client
from google import genai
from google.genai import types

# Load secret environment configurations from your hidden vault
load_dotenv()

app = FastAPI()

# 🛡️ UNIFY BROWSER DATA PIPELINES: Clears safety blocks for direct browser folder execution
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_scheme = HTTPBearer()

# Pull live credentials securely from background memory configuration files
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
AI_KEY = os.getenv("GEMINI_API_KEY")

if not all([SUPABASE_URL, SUPABASE_KEY, AI_KEY]):
    raise RuntimeError("Missing live cloud configuration keys inside your .env file.")

supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
ai_client = genai.Client(api_key=AI_KEY)

# DATA VALIDATION SCHEMAS
class AuthRequest(BaseModel):
    email: EmailStr
    password: str

class TransactionRequest(BaseModel):
    amount: float

class ChatRequest(BaseModel):
    message: str

class InvestRequest(BaseModel):
    pool_id: int
    shares_to_buy: float

class PaystackWebhookPayload(BaseModel):
    event: str
    data: dict

# SECURITY INTERCEPTOR GUARD: Validates active login sessions
def verify_secure_token(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    # Clean strings to remove accidental outer spaces or nested string double-quotes entirely
    raw_token = credentials.credentials.strip()
    token = raw_token.replace('"', '').replace("'", "")
    try:
        user_response = supabase_client.auth.get_user(token)
        return user_response.user.email
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired access token. Access Denied.")

@app.get("/")
def system_status():
    return {"status": "online", "investment_engine": "ACTIVE", "security": "ACTIVE"}

# --- AUTH & USER PROFILE PIPELINES ---
@app.post("/api/auth/signup")
def register_new_user(credentials: AuthRequest):
    try:
        auth_response = supabase_client.auth.sign_up({"email": credentials.email, "password": credentials.password})
        if not auth_response.user: 
            raise HTTPException(status_code=400, detail="Registration failed.")
        supabase_client.table("profiles").insert({"email": credentials.email, "token_balance": 0.00, "currency": "NGN"}).execute()
        return {"status": "success", "message": "Verification email successfully dispatched."}
    except Exception as e: 
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login")
def login_user(credentials: AuthRequest):
    try:
        session_response = supabase_client.auth.sign_in_with_password({"email": credentials.email, "password": credentials.password})
        return {"status": "success", "access_token": session_response.session.access_token}
    except Exception: 
        raise HTTPException(status_code=401, detail="Authentication failed. Incorrect email or password.")

@app.get("/api/dashboard/secure")
def get_secure_dashboard(authenticated_email: str = Depends(verify_secure_token)):
    try:
        response = supabase_client.table("profiles").select("*").eq("email", authenticated_email).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Financial profile record not found.")
        user_data = response.data[0] if isinstance(response.data, list) and len(response.data) > 0 else response.data
        tokens = float(user_data["token_balance"])
        return {
            "status": "success",
            "secured_account": user_data["email"],
            "available_tokens": tokens,
            "worth_in_naira": f"₦{tokens * 10000.00:,.2f}"
        }
    except Exception as e: 
        raise HTTPException(status_code=500, detail=str(e))

# --- WALLET PIPELINES (WEBHOOKS & PAYOUTS) ---
@app.post("/api/wallet/webhook/paystack")
def handle_external_wire_settlement(payload: PaystackWebhookPayload):
    if payload.event != "charge.success":
        raise HTTPException(status_code=400, detail="Event notification ignored.")
    try:
        target_customer_email = payload.data.get("customer", {}).get("email")
        deposited_fiat_naira = float(payload.data.get("amount", 0))
        if not target_customer_email or deposited_fiat_naira <= 0:
            raise HTTPException(status_code=422, detail="Incomplete settlement parameters parsed.")
        
        tokens_to_mint = deposited_fiat_naira / 10000.00
        response = supabase_client.table("profiles").select("token_balance").eq("email", target_customer_email).execute()
        user_data = response.data if isinstance(response.data, list) and len(response.data) > 0 else response.data
        if isinstance(user_data, list):
            user_data = user_data[0]
            
        current_tokens = float(user_data["token_balance"])
        new_total = current_tokens + tokens_to_mint
        supabase_client.table("profiles").update({"token_balance": new_total}).eq("email", target_customer_email).execute()
        return {"status": "success", "message": "External bank wire processed successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Webhook Execution Failure: {str(e)}")

@app.post("/api/wallet/withdraw")
def live_database_withdrawal(request: TransactionRequest, authenticated_email: str = Depends(verify_secure_token)):
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Withdrawal amount must be greater than zero.")
    try:
        response = supabase_client.table("profiles").select("token_balance").eq("email", authenticated_email).execute()
        user_data = response.data if isinstance(response.data, list) and len(response.data) > 0 else response.data
        if isinstance(user_data, list):
            user_data = user_data[0]
            
        current_tokens = float(user_data["token_balance"])
        if request.amount > current_tokens:
            raise HTTPException(status_code=400, detail="Insufficient token balance for this bank transfer wire.")
        new_total = current_tokens - request.amount
        supabase_client.table("profiles").update({"token_balance": new_total}).eq("email", authenticated_email).execute()
        return {"status": "success", "updated_balance_tokens": new_total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- LIVE METRIC INTEGRATION: INVESTMENT ENDPOINTS ---
@app.get("/api/investments/pools")
def get_investment_pools():
    try:
        response = supabase_client.table("investment_pools").select("*").execute()
        return {"status": "success", "pools": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database fetch failure: {str(e)}")

@app.post("/api/investments/allocate")
def allocate_tokens_to_pool(request: InvestRequest, authenticated_email: str = Depends(verify_secure_token)):
    if request.shares_to_buy <= 0:
        raise HTTPException(status_code=400, detail="Allocation shares must be greater than zero.")
    try:
        pool_res = supabase_client.table("investment_pools").select("*").eq("id", request.pool_id).execute()
        if not pool_res.data:
            raise HTTPException(status_code=404, detail="Target investment pool not found.")
        pool_data = pool_res.data if isinstance(pool_res.data, list) and len(pool_res.data) > 0 else pool_res.data
        if isinstance(pool_data, list):
            pool_data = pool_data[0]
            
        shares_available = float(pool_data["total_shares_available"]) - float(pool_data["shares_funded"])
        if request.shares_to_buy > shares_available:
            raise HTTPException(status_code=400, detail="Transaction rejected. Pool capacity overflow.")
            
        token_cost = request.shares_to_buy * float(pool_data["token_price_per_share"])
        profile_res = supabase_client.table("profiles").select("token_balance").eq("email", authenticated_email).execute()
        user_profile = profile_res.data if isinstance(profile_res.data, list) and len(profile_res.data) > 0 else profile_res.data
        if isinstance(user_profile, list):
            user_profile = user_profile[0]
            
        current_user_tokens = float(user_profile["token_balance"])
        if token_cost > current_user_tokens:
            raise HTTPException(status_code=400, detail="Insufficient funds for token allocation.")
            
        new_user_token_balance = current_user_tokens - token_cost
        supabase_client.table("profiles").update({"token_balance": new_user_token_balance}).eq("email", authenticated_email).execute()
        new_pool_funded_total = float(pool_data["shares_funded"]) + request.shares_to_buy
        supabase_client.table("investment_pools").update({"shares_funded": new_pool_funded_total}).eq("id", request.pool_id).execute()
        
        new_investment_log = {"user_email": authenticated_email, "pool_id": request.pool_id, "shares_purchased": request.shares_to_buy, "tokens_committed": token_cost}
        supabase_client.table("user_investments").insert(new_investment_log).execute()
        return {"status": "success", "message": f"Successfully allocated {token_cost} tokens.", "remaining_wallet_tokens": new_user_token_balance}
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=str(e))

# --- DIAGNOSTIC AI CARE SERVICE WITH RESILIENT FALLBACKS ---
@app.post("/api/support/chat")
def customer_care_chat(request: ChatRequest, authenticated_email: str = Depends(verify_secure_token)):
    try:
        ticket_query = supabase_client.table("support_tickets").select("*").eq("user_email", authenticated_email).execute()
        if not ticket_query.data:
            insert_res = supabase_client.table("support_tickets").insert({"user_email": authenticated_email, "chat_history": [], "status": "chatting_with_ai"}).execute()
            raw_insert = insert_res.data
            current_ticket = raw_insert if isinstance(raw_insert, list) and len(raw_insert) > 0 else raw_insert
        else:
            raw_query = ticket_query.data
            current_ticket = raw_query if isinstance(raw_query, list) and len(raw_query) > 0 else raw_query

        if isinstance(current_ticket, list):
            current_ticket = current_ticket[0]

        if current_ticket.get("status") == "needs_human":
            return {"status": "human_triage", "message": "Escalated to human supervisor."}
            
        history = current_ticket.get("chat_history", [])
        if history is None: history = []
        history.append({"role": "user", "text": request.message})
        
        if any(word in request.message.lower() for word in ["fraud", "stolen", "hack", "scam", "lost my money", "missing funds"]):
            supabase_client.table("support_tickets").update({"status": "needs_human", "chat_history": history}).eq("id", current_ticket["id"]).execute()
            return {"status": "human_triage", "message": "Warning keyword flagged. Routed to human supervisors."}
            
        system_instruction = "You are the care assistant for Naira.it. 1 Token = N10,000."
        full_prompt = f"System Rules:\n{system_instruction}\n\nUser Question:\n{request.message}"
        
        try:
            ai_response = ai_client.models.generate_content(model='gemini-3.8-flash', contents=full_prompt)
            ai_text = ai_response.text
        except Exception:
            ai_response = ai_client.models.generate_content(model='gemini-3.5-flash-lite', contents=full_prompt)
            ai_text = ai_response.text
            
        history.append({"role": "model", "text": ai_text})
        supabase_client.table("support_tickets").update({"chat_history": history}).eq("id", int(current_ticket["id"])).execute()
        return {"status": "ai_response", "message": ai_text}
    except Exception as general_crash:
        error_stack = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"[UNHANDLED EXCEPTION]:\n{error_stack}")
