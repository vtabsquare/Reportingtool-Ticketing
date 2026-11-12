# VTAB Ticket Center Architecture

## Boundary

Ticket Center is a new VTAB application. Desktop, Reporting Services, Admin
Console, and Reporting Manager remain unchanged. They integrate through signed
links and API calls described in `integrations/INTEGRATION_GUIDE.md`.

## Experiences

1. **Reporter portal** — submit evidence-rich issues and track only tickets the
   signed-in reporter owns.
2. **Developer operations** — triage, assign, investigate, add internal notes,
   and submit a resolution with a build plus commit or pull-request reference.
3. **Administrator sign-off** — verify the user experience, close a verified
   fix, or reopen it with actionable feedback.
4. **Desktop handoff** — create a short-lived signed diagnostic link without
   embedding sensitive report data in a URL.

## Lifecycle authority

`NEW → ASSIGNED → IN_PROGRESS → PENDING_ADMIN_SIGN_OFF → CLOSED`

Administrator rejection follows
`PENDING_ADMIN_SIGN_OFF → REOPENED → IN_PROGRESS`.

- Reporters cannot access another reporter's ticket.
- Developers cannot close tickets.
- A developer resolution requires notes, a fixed build, and a commit/PR.
- Closing requires administrator UX verification and notes.
- Every state change is written to the immutable application timeline.

## Data and files

- SQLite is used only for local development.
- `migrations/001_ticket_center_supabase.sql` is the production PostgreSQL /
  Supabase definition, including row-level security, indexes, private storage,
  realtime publication, and a database-level closure guard.
- Attachments are size-limited and stored using generated identifiers and safe
  filenames. Production downloads must use authenticated signed URLs.

## Authentication

Development accepts explicit test headers. Production must set
`VTAB_TICKET_AUTH_MODE=signed`; trusted VTAB backends issue short-lived HMAC
tokens containing subject, email, and role. Rotate the shared signing secret
through the deployment platform and expose the application only through HTTPS.

