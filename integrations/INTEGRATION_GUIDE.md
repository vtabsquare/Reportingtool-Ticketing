# Non-destructive VTAB ecosystem integration

The Ticket Center is intentionally independent. Existing Desktop, Services,
Admin Console, and Reporting Manager projects do not need to share its source.

## Desktop

Add a `Help > Report an Issue` command that calls the supplied
`desktop_ticket_launcher.open_ticket_portal`. Send only application version,
operating-system metadata, workspace ID, signed-in email, and a bounded recent
error excerpt. Never send credentials, report data, queries, or customer rows.

## Reporting Services

Add a support link to `${VTAB_TICKET_PUBLIC_URL}`. When a Services identity is
available, your identity service should mint a short-lived signed ticket token
with `sub`, `email`, and `role=user` claims. Do not accept role selection from a
production browser.

## Admin Console

Add a `Ticket Center` navigation link or iframe. Admin identities must receive
a server-signed `role=admin` claim. The Admin Console remains the exclusive
authority for `CLOSED` and `REOPENED` transitions.

## Reporting Manager / Developer portal

Link the Support Tickets navigation item to the Ticket Center with a signed
`developer` identity. Developers may assign, investigate, and submit a fixed
build for sign-off, but the API will reject any attempt to close a ticket.

## Production identity

Development mode permits `X-VTAB-User` and `X-VTAB-Role` headers for local
testing. Set `VTAB_TICKET_AUTH_MODE=signed` in production and issue the
`X-VTAB-Ticket-Token` from a trusted VTAB backend only.

