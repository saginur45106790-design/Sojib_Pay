# Sojib Pay v2 — Merchant Gateway Foundation

Mobile-first Node.js/Express + PostgreSQL project extended from the supplied Sojib Pay starter ZIP.

## What is included
- Existing customer sign-in, payment submission, support chat and admin payment review.
- Merchant application flow at `/merchant.html`.
- Admin merchant approval/suspension controls at `/admin.html`.
- Merchant API-key issuance (only after admin approval), revocation and a starter endpoint `POST /api/v1/payment-requests`.
- Request record lookup at `/checkout.html?id=...` and developer guide at `/developers.html`.
- SMS receipt intake at `POST /api/connector/sms-receipt`, with secret header and SHA-256 receipt hash validation; receipts are stored as `pending_review` and never automatically approve a payment.
- Payment records are no longer deleted 12 hours after approval/rejection. Keep an appropriate retention policy and backups.

## Critical production limitation
**This is not a live payment gateway yet.** It does not connect to official bKash, Nagad or Rocket APIs and does not collect or settle funds. The checkout URL displays a request record, not an actual wallet checkout. Before real payments, obtain provider/partner approval, implement their documented server-side APIs and callbacks, validate callback signatures, reconcile provider transaction records, and confirm applicable Bangladesh legal/regulatory requirements. Do not treat personal Send Money accounts as an authorized gateway.

SMS is not a source of cryptographic proof. Sender names may be spoofed; a sender label or `source_verified` field is not sufficient. The connector requires a separate, audited Android app or authorized provider integration. In this version all SMS receipts go to manual review. Never send SMS containing PINs, OTPs or full account secrets.

## Render environment
Set these in Render Dashboard > your web service > Environment:
- `NODE_ENV=production`
- `DATABASE_URL` (Render PostgreSQL connection string)
- `PGSSL=true` if required for the database connection
- `JWT_SECRET`: random secret, at least 32 characters
- `SMS_WEBHOOK_SECRET`: different random secret, at least 24 characters
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`: strong initial admin password

Never commit `.env` or real credentials to GitHub. If an existing service already has a database, keep the existing database URL; do not create a new database or change it without a backup.

## Run locally
1. Use Node.js 20+ and PostgreSQL.
2. `npm install`
3. Set environment variables (copy `.env.example` to `.env`).
4. `npm start`
5. Open `http://localhost:3000`, merchant console `/merchant.html`, developer guide `/developers.html`, admin `/admin.html`.

## Mobile deployment using GitHub + Render
1. Back up the existing repository and database before replacing files.
2. Extract this ZIP on your phone or upload its files to the existing GitHub repository (keep the project root files at repository root, not inside an extra nested folder).
3. Review changes, commit them to the branch linked to Render.
4. In Render, confirm the service is linked to the correct repository/branch and that `npm install` / `npm start` are configured. Render normally redeploys after a push to the connected branch.
5. Check the Deploys and Logs pages. Confirm `/api/health`, `/merchant.html`, `/developers.html`, and `/admin.html` load.
6. Sign in with a normal user account, open Merchant Console, submit the business application. Sign in as admin to `/admin.html` and approve only after checking the business.
7. Test payment requests with non-real/test data. Do not enable real payments until official provider APIs and required approvals are integrated.

## Key API routes
- `POST /api/merchant/apply` (session auth)
- `GET /api/merchant/me` (session auth)
- `POST /api/merchant/keys` (approved merchants only; secret displayed once)
- `POST /api/v1/payment-requests` with `X-SojibPay-Key` (approved merchant only)
- `GET /api/checkout/:publicId`
- `GET /api/admin/merchants` and `POST /api/admin/merchants/:id/status` (admin only)
- `GET /api/admin/sms-receipts` (admin only)
- `POST /api/connector/sms-receipt` with `X-SMS-Secret` (queues for manual review; never auto-approves)

This code is a development foundation and requires security review, integration tests, operational monitoring, backup/restore testing, and official provider integration before handling real money.
