import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const DEFAULT_CLIENT_ID = "vegvisr-app-auth";
const DEFAULT_REDIRECT = "https://auth.vegvisr.org/callback";

const ALLOWED_CLIENTS: Record<string, string[]> = {
	[DEFAULT_CLIENT_ID]: [
		DEFAULT_REDIRECT,
		"https://auth.vegvisr.org/callback/", // handle accidental trailing slash
		"https://auth-worker.torarnehave.workers.dev/callback", // workers.dev for testing
		"https://auth-worker.torarnehave.workers.dev/callback/",
	],
};

// This value should be shared between the OpenAuth server Worker and other
// client Workers that you connect to it, so the types and schema validation are
// consistent.
const subjects = createSubjects({
	user: object({
		id: string(),
	}),
});

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		const buildAuthorizeUrl = () => {
			const authorize = new URL(url.origin + "/authorize");
			authorize.searchParams.set("client_id", DEFAULT_CLIENT_ID);
			authorize.searchParams.set("redirect_uri", DEFAULT_REDIRECT);
			authorize.searchParams.set("response_type", "code");
			return authorize.toString();
		};

		const renderLanding = (title: string, description: string) => {
			const authorizeUrl = buildAuthorizeUrl();
			return new Response(
				`<!doctype html>
				<html lang="en">
				<head>
				  <meta charset="UTF-8" />
				  <meta name="viewport" content="width=device-width, initial-scale=1" />
				  <title>${title}</title>
				  <style>
				    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 0; background: #0b1b35; color: #eef2fb; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
				    .card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 32px; max-width: 420px; width: 90%; box-shadow: 0 20px 50px rgba(0,0,0,0.35); }
				    h1 { margin: 0 0 12px; font-size: 26px; letter-spacing: -0.2px; }
				    p { margin: 0 0 20px; line-height: 1.5; color: #cdd6f6; }
				    .btn { display: inline-flex; align-items: center; gap: 8px; background: linear-gradient(120deg, #4f8bff, #6ce0ff); color: #0a0f1f; border: none; border-radius: 12px; padding: 12px 18px; font-weight: 700; text-decoration: none; box-shadow: 0 8px 18px rgba(79,139,255,0.35); transition: transform 120ms ease, box-shadow 120ms ease; }
				    .btn:hover { transform: translateY(-1px); box-shadow: 0 10px 20px rgba(79,139,255,0.45); }
				    small { color: #9fb3ff; display: block; margin-top: 12px; }
				  </style>
				</head>
				<body>
				  <div class="card">
				    <h1>${title}</h1>
				    <p>${description}</p>
				    <a class="btn" href="${authorizeUrl}">Continue</a>
				    <small>We’ll send a code to your email to sign you in.</small>
				  </div>
				</body>
				</html>`,
				{
					status: 200,
					headers: { "Content-Type": "text/html; charset=utf-8" },
				},
			);
		};

		if (url.pathname === "/authorize") {
			const client = url.searchParams.get("client_id") ?? "";
			const redirect = url.searchParams.get("redirect_uri") ?? "";
			const allowed = ALLOWED_CLIENTS[client] ?? [];
			if (!allowed.includes(redirect)) {
				return new Response("unauthorized client/redirect", { status: 400 });
			}
		}

		if (url.pathname === "/") {
			return renderLanding("Vegvisr Auth", "Sign in or create your account to continue to the Vegvisr dashboard.");
		}

		if (url.pathname === "/login") {
			return renderLanding("Vegvisr Login", "Sign in securely. A one-time code will be sent to your email.");
		}

		if (url.pathname === "/register") {
			return renderLanding("Vegvisr Register", "Create your account with a magic code delivered to your email.");
		}

		if (url.pathname === "/callback") {
			return new Response("Callback is handled by your app worker", {
				status: 400,
			});
		}

		// The real OpenAuth server code starts here:
		return issuer({
			storage: CloudflareStorage({
				namespace: env.AUTH_STORAGE,
			}),
			subjects,
			providers: {
				password: PasswordProvider(
					PasswordUI({
						// eslint-disable-next-line @typescript-eslint/require-await
						sendCode: async (email: string, code: string) => {
							// This is where you would email the verification code to the
							// user, e.g. using Resend:
							// https://resend.com/docs/send-with-cloudflare-workers
							console.log(`Sending code ${code} to ${email}`);
						},
						copy: {
							input_code: "Code (check Worker logs)",
						},
					}),
				),
			},
			theme: {
				title: "myAuth",
				primary: "#0051c3",
				favicon: "https://workers.cloudflare.com//favicon.ico",
				logo: {
					dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
					light:
						"https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
				},
			},
			success: async (ctx: any, value: { email: string }) => {
				return ctx.subject("user", {
					id: await getOrCreateUser(env, value.email),
				});
			},
		}).fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;

async function getOrCreateUser(env: Env, email: string): Promise<string> {
	const result = await env.AUTH_DB.prepare(
		`
		INSERT INTO user (email)
		VALUES (?)
		ON CONFLICT (email) DO UPDATE SET email = email
		RETURNING id;
		`,
	)
		.bind(email)
		.first<{ id: string }>();
	if (!result) {
		throw new Error(`Unable to process user: ${email}`);
	}
	console.log(`Found or created user ${result.id} with email ${email}`);
	return result.id;
}
