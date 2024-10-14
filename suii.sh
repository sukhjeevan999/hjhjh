import { bech32 } from 'bech32';

/**
 * This returns an ParsedKeypair object based by validating the
 * 33-byte Bech32 encoded string starting with `suiprivkey`, and
 * parse out the signature scheme and the private key in bytes.
 */
export function decodeSuiPrivateKey(value: string): ParsedKeypair {
	const { prefix, words } = bech32.decode(value);
	if (prefix !== SUI_PRIVATE_KEY_PREFIX) {
		throw new Error('invalid private key prefix');
	}
	const extendedSecretKey = new Uint8Array(bech32.fromWords(words));
	const secretKey = extendedSecretKey.slice(1);
	const signatureScheme =
		SIGNATURE_FLAG_TO_SCHEME[extendedSecretKey[0] as keyof typeof SIGNATURE_FLAG_TO_SCHEME];
	return {
		schema: signatureScheme,
		secretKey: secretKey,
	};
}

/**
 * This returns a Bech32 encoded string starting with `suiprivkey`,
 * encoding 33-byte `flag || bytes` for the given the 32-byte private
 * key and its signature scheme.
 */
export function encodeSuiPrivateKey(bytes: Uint8Array, scheme: SignatureScheme): string {
	if (bytes.length !== PRIVATE_KEY_SIZE) {
		throw new Error('Invalid bytes length');
	}
	const flag = SIGNATURE_SCHEME_TO_FLAG[scheme];
	const privKeyBytes = new Uint8Array(bytes.length + 1);
	privKeyBytes.set([flag]);
	privKeyBytes.set(bytes, 1);
	return bech32.encode(SUI_PRIVATE_KEY_PREFIX, bech32.toWords(privKeyBytes));
}
