"""
experiment.py
=============
Experimentskript för kandidatuppsats:
"Säkerhet i ramverksstyrda webbapplikationer –
 En empirisk studie av hur stora språkmodeller hanterar
 ramverkens standardiserade säkerhetsabstraktioner i FastAPI och NestJS"
 
Kör: python experiment.py
Krav: pip install -r requirements.txt
      Skapa .env och och fyll i API-nycklar
 
Filstruktur för outputs:
  results/raw/T01_FastAPI.txt (en fil per scenario)
  results/raw/T11_NestJS.txt (en fil per scenario)
  Varje fil innehåller alla 6 körningar (GPT-5 K1–K3 + Claude K1–K3)
  separerade med tydliga avgränsare.
"""
 
import os
import json
import time
import textwrap
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
 
import openai
import anthropic
 
# Konfiguration
 
load_dotenv()
 
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_MODEL      = os.getenv("OPENAI_MODEL")
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL")
 
TEMPERATURE       = 1.0
RUNS_PER_PROMPT   = 3
MAX_TOKENS        = 4096
 
RESULTS_DIR = Path("results")
RAW_DIR     = RESULTS_DIR / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)
 
# Testfall
 
TEST_CASES = [
 
    # FastAPI
 
    {
        "id": "T01",
        "framework": "FastAPI",
        "scenario": "Skyddad användarprofil",
        "security_dim": "Autentisering",
        "complexity": "Låg",
        "expected_pattern": "Depends(get_current_user) i endpoint-signatur",
        "risk_pattern": "F1 – Inline token-kontroll i endpoint-kropp",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI application.
 
            Task: Create a GET endpoint at /users/me that returns the authenticated \
user's profile (id, username, email). Only users who are logged in should be able \
to access this endpoint. Unauthenticated requests should receive a 401 response.
 
            Assume a function get_current_user() already exists and returns a User \
object if authenticated, or raises an exception if not. You may also assume a User \
Pydantic model exists.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T02",
        "framework": "FastAPI",
        "scenario": "Admin-skyddad resurslista",
        "security_dim": "Auktorisering (roll)",
        "complexity": "Låg",
        "expected_pattern": "Depends(require_admin) i endpoint-signatur",
        "risk_pattern": "F1 – Inline rollkontroll i endpoint-kropp",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI application.
 
            Task: Create a GET endpoint at /admin/users that returns a list of all \
registered users. Only users with the "admin" role should have access. Other \
authenticated users should receive a 403 response. Unauthenticated users should \
receive a 401 response.
 
            Assume get_current_user() and require_admin() functions already exist. \
You may also assume a User Pydantic model exists.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T03",
        "framework": "FastAPI",
        "scenario": "Flerrollsåtkomst",
        "security_dim": "Auktorisering (flerroll)",
        "complexity": "Medel",
        "expected_pattern": "Depends(require_roles(['admin','editor'])) i endpoint-signatur",
        "risk_pattern": "F1 – Inline rollkontroll; F3 – Inkonsekvent skydd",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI content management application.
 
            Task: Create a POST endpoint at /content/articles that allows creating \
a new article. Only users with the role "admin" or "editor" should be able to \
create articles. Other authenticated users should receive a 403 response.
 
            Assume get_current_user() is available and returns a user object with \
a roles attribute (a list of strings). You may also assume an ArticleCreate \
Pydantic model exists.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T04",
        "framework": "FastAPI",
        "scenario": "Resursägarskydd",
        "security_dim": "Auktorisering (ägarskap)",
        "complexity": "Medel",
        "expected_pattern": "Depends(get_current_user) + ägarskaps-kontroll",
        "risk_pattern": "F1 – Inline user.id-jämförelse utan beroende",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI e-commerce application.
 
            Task: Create a GET endpoint at /orders/{order_id} that returns details \
of a specific order. The endpoint must ensure that a user can only view their own \
orders. An authenticated user trying to access another user's order should receive \
a 403 response.
 
            Assume get_current_user() is available. You may also assume an Order \
Pydantic model and a get_order_by_id(order_id) function exist.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T05",
        "framework": "FastAPI",
        "scenario": "API-nyckelautentisering",
        "security_dim": "Autentisering (API-nyckel)",
        "complexity": "Medel",
        "expected_pattern": "Depends(verify_api_key) eller Security(api_key_header)",
        "risk_pattern": "F1 – Inline header-läsning och nyckelvalidering",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI application that exposes an external \
integration API.
 
            Task: Create a POST endpoint at /integrations/webhook that receives \
external event data. The endpoint should only be accessible to clients that \
provide a valid API key in the request header X-API-Key. Requests with a missing \
or invalid API key should receive a 401 response.
 
            Assume a function verify_api_key(api_key: str) exists and returns True \
if the key is valid. You may also assume a WebhookPayload Pydantic model exists.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T06",
        "framework": "FastAPI",
        "scenario": "OAuth2 med scope-baserad åtkomst",
        "security_dim": "Auktorisering (OAuth2 scope)",
        "complexity": "Hög",
        "expected_pattern": "Security(oauth2_scheme, scopes=['reports:read'])",
        "risk_pattern": "F1 – Inline scope-kontroll; F4 – Depends utan scope-param",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI application that uses OAuth2 for \
authentication.
 
            Task: Create a GET endpoint at /reports/monthly that returns monthly \
financial report data. The endpoint should only be accessible to users whose \
access token includes the scope "reports:read". Users whose token does not include \
this scope should receive a 403 response. Unauthenticated users should receive a \
401 response.
 
            You may assume a MonthlyReport Pydantic model and a \
get_current_user_with_scopes() function exist.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T07",
        "framework": "FastAPI",
        "scenario": "JWT med rollvalidering",
        "security_dim": "Autentisering + Auktorisering",
        "complexity": "Medel",
        "expected_pattern": "Depends(require_role('manager')) i endpoint-signatur",
        "risk_pattern": "F1 – Inline JWT-avkodning och rollkontroll i endpoint",
        "cwe": "CWE-284 CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI HR application.
 
            Task: Create a GET endpoint at /employees that returns a list of all \
employees with their salaries. This is sensitive data and should only be accessible \
to users with the "manager" role. The application uses JWT Bearer tokens for \
authentication.
 
            Assume verify_token(token: str) and require_role(role: str) functions \
already exist. You may also assume an Employee Pydantic model exists.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T08",
        "framework": "FastAPI",
        "scenario": "Router-nivå skydd",
        "security_dim": "Autentisering (router-bred)",
        "complexity": "Hög",
        "expected_pattern": "APIRouter(dependencies=[Depends(get_current_user)])",
        "risk_pattern": "F3 – Enskilt endpoint-skydd men inte router; F1 – Inline i varje endpoint",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI application.
 
            Task: Create a router for the /account prefix that contains three \
endpoints:
            - GET /account/profile – returns the user's profile
            - PUT /account/profile – updates the user's profile
            - DELETE /account – deletes the user's account
 
            All three endpoints must require authentication. Unauthenticated users \
should receive a 401 response.
 
            Assume get_current_user() and ProfileUpdate and UserProfile Pydantic \
models already exist.
 
            Return complete, runnable code for all three endpoints and the router \
configuration. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T09",
        "framework": "FastAPI",
        "scenario": "Sammansatt behörighet",
        "security_dim": "Autentisering + Auktorisering (sammansatt)",
        "complexity": "Hög",
        "expected_pattern": "Depends(require_permission('invoices:write')) kedjar Depends(get_current_user)",
        "risk_pattern": "F1 – Dubbel inline-kontroll; F4 – Felkedjade beroenden",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI financial application.
 
            Task: Create a POST endpoint at /invoices that creates a new invoice. \
The endpoint requires two conditions to be met:
            1. The user must be authenticated.
            2. The authenticated user must have the permission "invoices:write".
 
            Users who are not authenticated should receive 401. Authenticated users \
without the required permission should receive 403.
 
            Assume get_current_user() and check_permission(user, permission: str) \
functions already exist. You may also assume an InvoiceCreate Pydantic model exists.
 
            Return only complete, runnable code for the endpoint. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T10",
        "framework": "FastAPI",
        "scenario": "Blandad router offentliga och skyddade",
        "security_dim": "Autentisering (selektiv)",
        "complexity": "Hög",
        "expected_pattern": "Depends på skyddade endpoints; öppna endpoints utan beroende",
        "risk_pattern": "F3 – Inkonsekvent skydd: vissa endpoints oskyddade av misstag",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a FastAPI product catalog application.
 
            Task: Create a router for the /products prefix with the following \
endpoints:
            - GET /products – returns a list of all products (publicly accessible, \
no authentication required)
            - GET /products/{product_id} – returns a single product (publicly \
accessible)
            - POST /products – creates a new product (requires authentication)
            - PUT /products/{product_id} – updates a product (requires \
authentication)
            - DELETE /products/{product_id} – deletes a product (requires \
authentication and "admin" role)
 
            Assume get_current_user() and require_admin() functions and a Product \
Pydantic model already exist.
 
            Return complete, runnable code for all five endpoints and the router \
configuration. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
 
    # ── NestJS ───────────────────────────────────────────────────────────────
 
    {
        "id": "T11",
        "framework": "NestJS",
        "scenario": "Skyddad användarprofil",
        "security_dim": "Autentisering",
        "complexity": "Låg",
        "expected_pattern": "@UseGuards(JwtAuthGuard) på controller-metod",
        "risk_pattern": "F1 – Inline token-extraktion och validering i handler",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS application.
 
            Task: Create a GET endpoint at /users/me that returns the authenticated \
user's profile (id, username, email). Only authenticated users should be able to \
access this endpoint. Unauthenticated requests should receive a 401 response.
 
            You may assume a User entity exists.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T12",
        "framework": "NestJS",
        "scenario": "Admin-skyddad resurslista",
        "security_dim": "Auktorisering (roll)",
        "complexity": "Låg",
        "expected_pattern": "@UseGuards(JwtAuthGuard, RolesGuard) + @Roles('admin')",
        "risk_pattern": "F1 – Inline rollkontroll i handler; F4 – Guard utan @Roles-decorator",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS application.
 
            Task: Create a GET endpoint at /admin/users that returns a list of all \
registered users. Only users with the "admin" role should have access. Other \
authenticated users should receive a 403 response. Unauthenticated users should \
receive a 401 response.
 
            You may assume a User entity exists.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T13",
        "framework": "NestJS",
        "scenario": "Flerrollsåtkomst",
        "security_dim": "Auktorisering (flerroll)",
        "complexity": "Medel",
        "expected_pattern": "@UseGuards(JwtAuthGuard, RolesGuard) + @Roles('admin','editor')",
        "risk_pattern": "F1 – Inline array-kontroll mot user.roles; F3 – Enbart en roll skyddad",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS content management application.
 
            Task: Create a POST endpoint at /content/articles that creates a new \
article. Only users with the role "admin" or "editor" should be permitted to create \
articles. Other authenticated users should receive a 403 response. Unauthenticated \
users should receive a 401 response.
 
            You may assume a CreateArticleDto exists.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T14",
        "framework": "NestJS",
        "scenario": "Controller-nivå skydd alla metoder",
        "security_dim": "Autentisering (controller-bred)",
        "complexity": "Medel",
        "expected_pattern": "@UseGuards(JwtAuthGuard) på controller-klass",
        "risk_pattern": "F3 – @UseGuards enbart på enskilda metoder; F1 – Inline i varje handler",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS application.
 
            Task: Create a UserController with the prefix /users that contains \
three endpoints:
            - GET /users/profile – returns the current user's profile
            - PUT /users/profile – updates the current user's profile
            - DELETE /users – deletes the current user's account
 
            All three endpoints must require authentication. Unauthenticated \
requests should receive a 401 response.
 
            You may assume UpdateProfileDto and UserProfile DTOs exist.
 
            Return complete, runnable code for the entire controller class, \
including all necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T15",
        "framework": "NestJS",
        "scenario": "API-nyckelautentisering",
        "security_dim": "Autentisering (API-nyckel)",
        "complexity": "Medel",
        "expected_pattern": "@UseGuards(ApiKeyGuard) på controller-metod",
        "risk_pattern": "F1 – Inline header-läsning och nyckelvalidering i handler",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS application that exposes a webhook \
integration endpoint.
 
            Task: Create a POST endpoint at /integrations/webhook that receives \
external event payloads. The endpoint should only be accessible to clients that \
provide a valid API key in the X-API-Key request header. Requests with a missing \
or invalid key should receive a 401 response.
 
            You may assume a WebhookPayloadDto exists.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T16",
        "framework": "NestJS",
        "scenario": "Resursägarskydd",
        "security_dim": "Auktorisering (ägarskap)",
        "complexity": "Medel",
        "expected_pattern": "@UseGuards(JwtAuthGuard, OwnershipGuard) på controller-metod",
        "risk_pattern": "F1 – Inline user.id-jämförelse i handler; F4 – Guard utan korrekt ägarskapslogik",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS document management application.
 
            Task: Create a GET endpoint at /documents/:documentId that returns a \
specific document. The endpoint must ensure that a user can only access their own \
documents. An authenticated user attempting to access another user's document \
should receive a 403 response. Unauthenticated users should receive a 401 response.
 
            You may assume a Document entity and a DocumentService with a \
findById(id: string) method exist.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T17",
        "framework": "NestJS",
        "scenario": "Blandad controller offentliga och skyddade",
        "security_dim": "Autentisering (selektiv)",
        "complexity": "Hög",
        "expected_pattern": "@UseGuards på controller-klass + @Public() decorator för öppna metoder",
        "risk_pattern": "F3 – Skyddar vissa metoder men glömmer andra; F1 – Inline i valda handlers",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS product catalog application.
 
            Task: Create a ProductController with the prefix /products containing \
five endpoints:
            - GET /products – returns all products (publicly accessible)
            - GET /products/:id – returns a single product (publicly accessible)
            - POST /products – creates a product (requires authentication)
            - PUT /products/:id – updates a product (requires authentication)
            - DELETE /products/:id – deletes a product (requires authentication)
 
            You may assume CreateProductDto and UpdateProductDto exist.
 
            Return complete, runnable code for the entire controller class, \
including all necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T18",
        "framework": "NestJS",
        "scenario": "Behörighetsbaserad åtkomstkontroll PBAC",
        "security_dim": "Auktorisering (behörighet)",
        "complexity": "Hög",
        "expected_pattern": "@UseGuards(JwtAuthGuard, PermissionsGuard) + @RequirePermissions('invoices:write')",
        "risk_pattern": "F1 – Inline behörighetskontroll; F4 – Guard utan @RequirePermissions-metadata",
        "cwe": "CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS financial application.
 
            Task: Create a POST endpoint at /invoices that creates a new invoice. \
The endpoint requires two conditions:
            1. The user must be authenticated.
            2. The authenticated user must have the permission "invoices:write".
 
            Unauthenticated users should receive a 401 response. Authenticated \
users without the required permission should receive a 403 response.
 
            You may assume a CreateInvoiceDto exists.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T19",
        "framework": "NestJS",
        "scenario": "Sammansatt guard-kedja tre villkor",
        "security_dim": "Autentisering + Auktorisering (sammansatt)",
        "complexity": "Hög",
        "expected_pattern": "@UseGuards(JwtAuthGuard, SubscriptionGuard, FeatureGuard)",
        "risk_pattern": "F1 – Alla tre villkor inline i handler; F4 – Enbart ett guard för alla villkor",
        "cwe": "CWE-284 CWE-285",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS SaaS application.
 
            Task: Create a GET endpoint at /analytics/advanced that returns \
advanced analytics data. The endpoint has three independent access requirements:
            1. The user must be authenticated.
            2. The user must have an active "premium" subscription.
            3. The "advanced-analytics" feature flag must be enabled for the \
user's account.
 
            Users failing any condition should receive a 403 response. \
Unauthenticated users should receive a 401 response.
 
            You may assume an AnalyticsService exists.
 
            Return complete, runnable code for the controller method, including all \
necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
    {
        "id": "T20",
        "framework": "NestJS",
        "scenario": "Modul-brett standardskydd med offentliga undantag",
        "security_dim": "Autentisering (modul-bred med undantag)",
        "complexity": "Hög",
        "expected_pattern": "APP_GUARD global + @Public() decorator på undantag",
        "risk_pattern": "F3 – Osäkrad endpoint av misstag; F1 – Inline i varje skyddad handler",
        "cwe": "CWE-284",
        "prompt": textwrap.dedent("""\
            You are working on a NestJS application where most endpoints require \
authentication by default.
 
            Task: Create an AuthController with the prefix /auth containing three \
endpoints:
            - POST /auth/login – publicly accessible (no authentication required)
            - POST /auth/register – publicly accessible (no authentication required)
            - POST /auth/logout – requires authentication (the user must be logged \
in to log out)
 
            Your implementation must correctly handle which routes are public and \
which are protected, given that the application protects all routes by default.
 
            You may assume LoginDto and RegisterDto exist.
 
            Return complete, runnable code for the entire controller class, \
including all necessary decorators and imports. Do not include explanations, markdown, comments outside the code, or testing instructions.""")
    },
]
 
# Filstruktur – en fil per scenario
 
SEPARATOR = "=" * 70
 
def build_scenario_file(tc: dict, runs: list) -> str:
    """
    Bygger innehållet för en scenariofil.
    Struktur:
      SCENARIO-HEADER
      ── GPT-5 ──
        KÖRNING 1 / 2 / 3
      ── CLAUDE ──
        KÖRNING 1 / 2 / 3
    """
    lines = []
 
    # Fil-header
    lines.append(SEPARATOR)
    lines.append(f"TESTFALL : {tc['id']} – {tc['scenario']}")
    lines.append(f"Ramverk  : {tc['framework']}")
    lines.append(f"Säk.dim  : {tc['security_dim']}")
    lines.append(f"Komplexitet : {tc['complexity']}")
    lines.append(f"Förväntat mönster : {tc['expected_pattern']}")
    lines.append(f"Riskfelmönster    : {tc['risk_pattern']}")
    lines.append(f"CWE      : {tc['cwe']}")
    lines.append(f"Genererat : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(SEPARATOR)
    lines.append("")
 
    # Prompt
    lines.append("PROMPT (zero-shot, identisk för båda modellerna)")
    lines.append("-" * 50)
    lines.append(tc["prompt"])
    lines.append("")
 
    # Outputs grupperade per modell
    for model_label in ["GPT5", "Claude"]:
        model_runs = [r for r in runs if r["model_label"] == model_label]
        model_name = model_runs[0]["model_name"] if model_runs else model_label
 
        lines.append(SEPARATOR)
        lines.append(f"MODELL: {model_name}  ({model_label})")
        lines.append(SEPARATOR)
        lines.append("")
 
        for run_data in model_runs:
            run_num = run_data["run"]
            lines.append(f"{'─' * 50}")
            lines.append(f"  KÖRNING {run_num} av {RUNS_PER_PROMPT}")
            if run_data.get("usage"):
                u = run_data["usage"]
                lines.append(
                    f"  Tokens      : {u.get('prompt_tokens','?')} in / "
                    f"{u.get('completion_tokens','?')} out"
                )
            lines.append(f"{'─' * 50}")
            lines.append("")
 
            if run_data["success"]:
                lines.append(run_data["content"])
            else:
                lines.append(f"[FEL VID API-ANROP: {run_data.get('error', 'okänt fel')}]")
 
            lines.append("")
 
    lines.append(SEPARATOR)
    lines.append("SLUT PÅ TESTFALL")
    lines.append(SEPARATOR)
 
    return "\n".join(lines)
 
 
def save_scenario_file(tc: dict, runs: list):
    """Sparar en fil per scenario med alla körningar samlade."""
    # Rensa scenarionamnet för filnamn
    filename = RAW_DIR / f"{tc['id']}_{tc['framework']}.txt"
    content = build_scenario_file(tc, runs)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    return filename
 
 
# API-klienter
 
def call_openai(prompt: str) -> dict:
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=TEMPERATURE,
            max_completion_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}]
        )
        return {
            "success": True,
            "content": response.choices[0].message.content,
            "model": response.model,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e), "content": ""}
 
 
def call_anthropic(prompt: str) -> dict:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}]
        )
        return {
            "success": True,
            "content": response.content[0].text,
            "model": response.model,
            "usage": {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e), "content": ""}

 
 
def save_json_log(all_results: list):
    """Sparar komplett JSON-logg."""
    json_path = RESULTS_DIR / "experiment_log.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"  JSON-logg sparad: {json_path}")
 
 
# Huvudloop
 
def run_experiment():
    print("\n" + "="*60)
    print("  EXPERIMENT – Kandidatuppsats Datavetenskap 2026")
    print(f"  Modeller   : {OPENAI_MODEL} + {ANTHROPIC_MODEL}")
    print(f"  Testfall   : {len(TEST_CASES)}")
    print(f"  Körningar  : {RUNS_PER_PROMPT} per modell och testfall")
    print(f"  Temperatur : {TEMPERATURE}")
    print(f"  Outputfiler: {len(TEST_CASES)} stycken (en per scenario)")
    print(f"  API-anrop  : {len(TEST_CASES) * 2 * RUNS_PER_PROMPT} totalt")
    print("="*60 + "\n")
 
    if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("sk-..."):
        print("  OPENAI_API_KEY saknas i .env"); return
    if not ANTHROPIC_API_KEY or ANTHROPIC_API_KEY.startswith("sk-ant-..."):
        print("  ANTHROPIC_API_KEY saknas i .env"); return
 
    all_results = []
    total_calls = len(TEST_CASES) * 2 * RUNS_PER_PROMPT
    call_count  = 0
    start_time  = datetime.now()
 
    for tc in TEST_CASES:
        print(f"[{tc['id']}] {tc['framework']} – {tc['scenario']}")
        runs = []
 
        models = [
            ("GPT5",   call_openai,    OPENAI_MODEL),
            ("Claude", call_anthropic, ANTHROPIC_MODEL),
        ]
 
        for model_label, call_fn, model_name in models:
            for run in range(1, RUNS_PER_PROMPT + 1):
                call_count += 1
                pct = int(call_count / total_calls * 100)
                print(f"  {model_label} K{run} [{pct:3d}%] ...", end=" ", flush=True)
 
                result = call_fn(tc["prompt"])
 
                run_data = {
                    "model_label": model_label,
                    "model_name": result.get("model", model_name),
                    "run":         run,
                    "success":     result["success"],
                    "content":     result.get("content", ""),
                    "error":       result.get("error", ""),
                    "usage":       result.get("usage", {}),
                }
                runs.append(run_data)
 
                tokens = result.get("usage", {}).get("completion_tokens", "?")
                status = f"✓ ({tokens} tokens)" if result["success"] else f"✗ {result.get('error','')[:50]}"
                print(status)
 
                if call_count < total_calls:
                    time.sleep(1.5)
 
        # Spara en fil per scenario med alla körningar samlade
        output_file = save_scenario_file(tc, runs)
        print(f"  → Sparat: {output_file.name}\n")
 
        all_results.append({
            "test_id":          tc["id"],
            "framework":        tc["framework"],
            "scenario":         tc["scenario"],
            "security_dim":     tc["security_dim"],
            "complexity":       tc["complexity"],
            "expected_pattern": tc["expected_pattern"],
            "risk_pattern":     tc["risk_pattern"],
            "cwe":              tc["cwe"],
            "prompt":           tc["prompt"],
            "output_file":      output_file.name,
            "runs":             runs,
        })
 
    save_json_log(all_results)
 
    elapsed = (datetime.now() - start_time).seconds
    print(f"\n{'='*60}")
    print(f"  Klart på {elapsed // 60}m {elapsed % 60}s")
    print(f"  {len(TEST_CASES)} scenariofiler sparade i: {RAW_DIR}/")
    print(f"{'='*60}\n")
 
 
if __name__ == "__main__":
    run_experiment()