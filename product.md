# TrialGuard — product facts

Source of truth for sales and marketing. Only claims listed under "What it does" may be made.

## What it does
- Web tool: the customer uploads or pastes a CSV export of their signups (free-trial or free-plan users).
- Finds accounts that are probably the same person or throwaway signups, using these rules:
  - Same inbox: Gmail dot variants and "+tag" aliases (Gmail, Outlook/Hotmail, iCloud, Proton, Fastmail, Zoho, Yandex, GMX, HEY).
  - 3 or more signups from one IP within 24 hours (needs IP and signup date columns).
  - 5 or more signups from one IP overall (flagged lower; could be an office or school).
  - Same browser (user agent) on the same IP.
  - Disposable email domains (about 100 known services such as mailinator.com, 10minutemail.com, yopmail.com).
  - Numbered aliases on free mail providers (name1@, name2@, name3@).
  - The customer's own device/fingerprint id column, if they have one.
- Gives each flagged account a 0–100 risk score with a plain-English reason for every flag.
- Lists linked account groups.
- Flagged accounts can be downloaded as a CSV.
- Only an email column is required; IP, user agent, signup date, device id and user id are optional. Column names are detected automatically (English or Turkish), comma/semicolon/tab separated files work.
- Up to 50,000 signups per file.
- Results appear immediately after uploading (typical files are analyzed in seconds).
- Privacy: the list is analyzed in memory and never stored. No account or signup needed to use it.
- Interface language: English.

## What it does NOT do (never claim these)
- No API, SDK, JavaScript snippet, webhook or integration with the customer's product or signup flow.
- Does not block, stop or prevent signups automatically, and does not act in real time. It analyzes a list after the fact; the customer decides what to do.
- Does not clean, edit, merge or delete anything: it never produces a "cleaned list"; it only flags accounts and lets you download the flagged ones.
- Does not create device fingerprints itself; it only uses a device id column if the customer already has one.
- No IP geolocation, VPN/proxy/Tor detection, phone or payment-card checks.
- No AI or machine learning; it uses transparent rules.
- No dashboard, user accounts, history or saved reports; nothing is stored.
- No measured accuracy, false-positive rate, customers, case studies or savings figures exist.

## Pricing and offer
- Using the tool is currently free; there is no paid plan or payment page yet.
- "I want to buy" on the site only collects an email; payment details are sent manually afterwards.
- Do not quote prices, trials, pilots, quotas or check limits other than the 50,000-signup file limit.

## Good fit
Small SaaS / AI tools with a free trial or free plan where repeat signups cost money (LLM tokens, compute, credits) and who can export a signup list (email, ideally IP and signup time).
