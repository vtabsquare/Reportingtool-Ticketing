# VTAB Ticket Center 1.0.0

A standalone, centralized ticket-management add-on for the VTAB ecosystem.
It does not replace or modify Reporting Studio, Reporting Services, Admin
Console, or Reporting Manager.

## Included experiences

- **Reporter portal:** rich issue form, diagnostic handoff, attachments, and personal ticket history.
- **Developer portal:** priority queue, assignment, investigation, resolution build, commit/PR reference, and verification notes.
- **Administrator desk:** pending sign-off queue, user-experience verification, reopen feedback, and exclusive ticket closure.
- **Central API:** role enforcement, state-machine validation, attachment controls, audit timeline, comments, and real-time event stream.
- **Production migration:** Supabase/PostgreSQL tables, indexes, storage bucket, RLS, realtime publication, and database closure guard.

## Run locally

```powershell
python run_ticket_center.py
```

The launcher installs missing packages from `requirements.txt`, opens the
browser, and starts the application at `http://127.0.0.1:8860`.

For controlled setup:

```powershell
python -m venv .ticket-venv
.\.ticket-venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python run_ticket_center.py
```

## Local role testing

Use the **View as** selector to test Reporter, Developer, and Administrator.
This selector works only because `.env.example` defaults to development auth.
Production must use signed tokens issued by a trusted VTAB backend.

## Tests

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app integrations
```

## Production

1. Apply `migrations/001_ticket_center_supabase.sql` to the dedicated Supabase project.
2. Configure the environment variables in `.env.example` through the deployment platform.
3. Set `VTAB_TICKET_AUTH_MODE=signed` and rotate the signing secret.
4. Place the API behind HTTPS and an authenticated VTAB identity issuer.
5. Integrate products only through `integrations/INTEGRATION_GUIDE.md`.

