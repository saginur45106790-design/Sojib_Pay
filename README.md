# Sojib Pay (starter)

A mobile-first payment submission and support prototype for BDT Send Money workflows.

## Important limitations

- This is a **starter project**, not a production-ready payment gateway.
- It does not read Android SMS by itself. `/api/connector/sms-receipt` accepts an authenticated receipt from a separate, audited Android connector.
- `source_verified: true` is only a claim from that connector, not proof by itself. Do not enable automatic approval for real money until the collector validates trusted sender metadata and the wallet's receipt format, and you have tested it thoroughly.
- SMS sender names/numbers can be spoofed in some contexts. A transaction record from the wallet provider is more authoritative than SMS alone.
- This project uses personal Send Money account settings, not official merchant settlement. Check each wallet provider's terms before collecting business payments.
- The app does not implement file uploads for screenshots. Customers can paste transaction details in support chat; add secure file storage with file-type checks, malware scanning and access controls before allowing evidence uploads.
- The 12-hour cleanup deletes finalized payment records. This can conflict with accounting, chargeback handling, legal retention and duplicate prevention. Get appropriate advice and retain only the minimum non-sensitive deduplication data needed. Do not use this default blindly in production.
- Live chat is implemented as authenticated polling plus WebSocket refresh hints, not a guaranteed always-connected helpdesk.
- Render free services/databases may sleep, have limited persistence/availability, or change plan limits. Production payments need reliable paid hosting, backups and monitoring.

## Local development

1. Install Node.js 20+ and PostgreSQL.
2. Create a database named `sojibpay`.
3. Copy `.env.example` to `.env`.
4. Set a long random `JWT_SECRET`, a different long random `SMS_WEBHOOK_SECRET`, and a strong `ADMIN_PASSWORD`.
5. Set `DATABASE_URL` to your PostgreSQL connection string.
6. Run `npm install`, then `npm start`.
7. Open `http://localhost:3000`; admin UI is at `/admin.html`.

## Render deployment

1. Push this folder to a private GitHub repository.
2. In Render, create a PostgreSQL database and a Web Service from the repository.
3. Set `DATABASE_URL` to the database's internal connection string and `PGSSL=true` if required.
4. Set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_SECRET`, `SMS_WEBHOOK_SECRET`. Never commit `.env`.
5. Deploy. Visit `/admin.html`, sign in, and configure wallet account numbers.
6. Test using small, authorized test payments before public launch. Add a real Android SMS collector only after security review.

## API outline

- `POST /api/auth/signup`, `POST /api/auth/login`, `POST /api/auth/logout`
- `POST /api/payments`, `GET /api/payments/mine`
- `GET /api/support/:paymentId`, `POST /api/support/:paymentId`
- `GET /api/admin/overview`, `GET /api/admin/payments`
- `POST /api/admin/payments/:id/decision`
- `GET /api/admin/settings`, `PUT /api/admin/settings/:provider`
- `POST /api/connector/sms-receipt` (requires `X-SMS-Secret` header)

The starter is intentionally not configured to accept uploaded evidence or to blindly trust arbitrary SMS content.
