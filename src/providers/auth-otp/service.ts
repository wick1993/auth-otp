import {
	AbstractAuthModuleProvider,
	MedusaError,
} from "@medusajs/framework/utils";
import type {
	AuthIdentityProviderService,
	AuthenticationInput,
	AuthenticationResponse,
} from "@medusajs/framework/types";
import Scrypt from "scrypt-kdf";

class AuthOTPProviderService extends AbstractAuthModuleProvider {
	static identifier = "auth-otp";
	static DISPLAY_NAME = "Mobile Authentication";
	// TODO implement methods
	async authenticate(
		data: AuthenticationInput,
		authIdentityProviderService: AuthIdentityProviderService,
	): Promise<AuthenticationResponse> {
		if (!data.body) {
			return {
				success: false,
				error: "Invalid request body please provide phone number",
			};
		}
		// if (data.body.otp !== '1234') {
		// 	return {
		// 		success: false,
		// 		error: 'Invalid OTP',
		// 	};
		// }
		const authIdentity = await authIdentityProviderService.retrieve({
			entity_id: data.body.phone,
		});

		const password = data.body.password;
		const provider_identitiy = authIdentity.provider_identities?.[0] || null;
		if (!provider_identitiy) {
			return {
				success: false,
				error: "No provider identity found",
			};
		}

		const passwordHash = provider_identitiy?.provider_metadata
			?.password as string;
		if (!passwordHash) {
			return {
				success: false,
				error: "No password found for this identity",
			};
		}

		const isValid = await this.verifyPassword(passwordHash, password);

		return {
			success: isValid,
			authIdentity,
		};
	}

	async register(
		data: AuthenticationInput,
		authIdentityProviderService: AuthIdentityProviderService,
	): Promise<AuthenticationResponse> {
		if (!data.body) {
			return {
				success: false,
				error: "Invalid request body please provide phone number",
			};
		}
		try {
			await authIdentityProviderService.retrieve({
				entity_id: data.body.phone, // email or some ID
			});
			return {
				success: false,
				error: "Identity with phone number already exists",
			};
		} catch (error) {
			if (error.type === MedusaError.Types.NOT_FOUND) {
				const passwordHash = await this.hashPassword(data.body.password);
				const createdAuthIdentity = await authIdentityProviderService.create({
					entity_id: data.body.phone, // email or some ID
					user_metadata: {
						phone: data.body.phone,
					},
					provider_metadata: {
						phone: data.body.phone,
						password: passwordHash,
					},
				});
				return {
					success: true,
					authIdentity: createdAuthIdentity,
				};
			}
			return { success: false, error: error.message };
		}
	}

	async hashPassword(password: string) {
		const hashConfig = { logN: 15, r: 8, p: 1 };
		const passwordHash = await Scrypt.kdf(password, hashConfig);
		return passwordHash.toString("base64");
	}

	async verifyPassword(
		storedHash: string,
		inputPassword: string,
	): Promise<boolean> {
		try {
			const isMatch = await Scrypt.verify(
				Buffer.from(storedHash, "base64"),
				inputPassword,
			);
			return isMatch;
		} catch (error) {
			console.error("Error verifying password:", error);
			return false;
		}
	}
}

export default AuthOTPProviderService;
