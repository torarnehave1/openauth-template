import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const ALLOWED_CLIENTS = {
	"vegvisr-app-auth": ["https://auth.vegvisr.org/callback"],
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

		if (url.pathname === "/authorize") {
			const client = url.searchParams.get("client_id") ?? "";
			const redirect = url.searchParams.get("redirect_uri") ?? "";
			const allowed = ALLOWED_CLIENTS[client] ?? [];
			if (!allowed.includes(redirect)) {
				return new Response("unauthorized client/redirect", { status: 400 });
			}
		}

		if (url.pathname === "/") {
			url.searchParams.set("redirect_uri", "https://auth.vegvisr.org/callback");
			url.searchParams.set("client_id", "vegvisr-app-auth");
			url.searchParams.set("response_type", "code");
			url.pathname = "/authorize";
			return Response.redirect(url.toString());
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
						sendCode: async (email, code) => {
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
			success: async (ctx, value) => {
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
