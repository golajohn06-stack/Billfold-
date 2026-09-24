# Billfold: deploy and start charging

1. In Stripe, create a product "Billfold Pro" with a $9/month recurring price. Copy the price ID.
2. In Stripe > Developers > Webhooks, add endpoint `https://YOUR-DOMAIN/webhook` for events
   `checkout.session.completed` and `customer.subscription.deleted`. Copy the signing secret.
3. Deploy this folder to Render, Railway, or Fly.io with these environment variables:
   - `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`
   - `BASE_URL` (your public URL, no trailing slash)
   - `RESEND_API_KEY` and `MAIL_FROM` (create a free Resend account, verify your domain, and use an address like `Billfold <hello@yourdomain.com>`; without these, reset links print to the server log)
   - `TOKEN_SECRET` (any long random string)
4. Use Stripe test mode first (card 4242 4242 4242 4242), then switch to live keys.

Accounts: people sign up with email and password, invoices sync across devices, and Pro belongs to the account.
Data lives in data.json (set `DB_PATH` to a file on a persistent disk, or move to Postgres before real scale).

Known MVP limits: the free limit is counted from saved invoices (a determined user can bypass it, and signed-out
users can clear their browser), rate limits are in memory (they reset on restart), and there is no customer portal for
cancellations (enable Stripe's hosted portal link).

## Fastest deploy (Render)
Push this folder to GitHub, then in Render choose New > Blueprint and select the repo (`render.yaml` sets up the
Docker service and a small persistent disk). Fill in the environment variables from `.env.example`.
Also enable Stripe's Customer Portal (Settings > Billing > Customer portal) so Manage plan works.

## Test before launch
Locally: `npm install`, then run `STRIPE_SECRET_KEY=sk_test_x TOKEN_SECRET=test npm start` in one terminal and
`npm run smoke` in another. It checks signup, the free limit, login, logout, and password reset. Then do one
real checkout in Stripe test mode with card 4242 4242 4242 4242.
