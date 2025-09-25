```markdown
# Weather Backend (Node.js + Express + PostgreSQL)


## Setup


1. Copy `.env.example` -> `.env` and fill values.
2. Create a Postgres database and set `DATABASE_URL`.
3. Run the SQL schema to create tables:


```bash
psql -U youruser -d yourdb -f sql/postgresql-schema.sql
```


4. Install dependencies:


```bash
npm install
```


5. Start the dev server:


```bash
npm run dev
```


6. Update your frontend to use these endpoints:


- POST `/api/auth/signup` with `{ name, email, password }`
- POST `/api/auth/login` with `{ email, password }`
- GET `/api/auth/me` with `Authorization: Bearer <token>` header


The server runs on `http://localhost:4000` by default.
```