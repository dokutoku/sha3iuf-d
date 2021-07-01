/*
 * -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input.
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use.
 *
 * I would appreciate if you give credits to this work if you used it to
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ----------------------------------------------------------------------
 */
module sha3iuf_d.sha3;


version (WebAssembly) {
} else {
	version = SHA3IUF_D_ENABLE_UNITTEST;
}

/* 'Words' here refers to ulong */
///
extern (C)
public enum SHA3_KECCAK_SPONGE_WORDS = (1600 / 8 /*bits to byte*/) / ulong.sizeof;

///
extern (C)
public struct sha3_context
{
	/*
	 * the portion of the input message that we
	 * didn't consume yet
	 */
	ulong saved;

	union u_
	{
		/* Keccak's state */
		ulong[.SHA3_KECCAK_SPONGE_WORDS] s;
		ubyte[.SHA3_KECCAK_SPONGE_WORDS * 8] sb;
	}

	u_ u;

	/*
	 * 0..7--the next byte after the set one
	 * (starts from 0; 0--none are buffered)
	 */
	uint byteIndex;

	/*
	 * 0..24--the next word to integrate input
	 * (starts from 0)
	 */
	uint wordIndex;

	/*
	 * the double size of the hash output in
	 * words (e.g. 16 for Keccak 512)
	 */
	uint capacityWords;
}

///
extern (C)
public enum SHA3_FLAGS
{
	SHA3_FLAGS_NONE = 0,
	SHA3_FLAGS_KECCAK = 1,
}

//Declaration name in C language
public enum
{
	SHA3_FLAGS_NONE = .SHA3_FLAGS.SHA3_FLAGS_NONE,
	SHA3_FLAGS_KECCAK = .SHA3_FLAGS.SHA3_FLAGS_KECCAK,
}

///
extern (C)
public enum SHA3_RETURN
{
	SHA3_RETURN_OK = 0,
	SHA3_RETURN_BAD_PARAMS = 1,
}

//Declaration name in C language
public enum
{
	SHA3_RETURN_OK = .SHA3_RETURN.SHA3_RETURN_OK,
	SHA3_RETURN_BAD_PARAMS = .SHA3_RETURN.SHA3_RETURN_BAD_PARAMS,
}

///
public alias sha3_return_t = .SHA3_RETURN;

//#define SHA3_TRACE(format, ...)
//#define SHA3_TRACE_BUF(format, buf, l)

/*
 * This flag is used to configure "pure" Keccak, as opposed to NIST SHA3.
 */
private enum SHA3_USE_KECCAK_FLAG = 0x80000000;

pragma(inline, true)
pure nothrow @safe @nogc @live
private ulong SHA3_CW(uint x)

	do
	{
		return x & ~SHA3_USE_KECCAK_FLAG;
	}

pragma(inline, true)
pure nothrow @safe @nogc @live
private ulong SHA3_ROTL64(ulong x, ulong y)

	do
	{
		return (x << y) | (x >> ((ulong.sizeof * 8) - y));
	}

private static immutable ulong[24] keccakf_rndc = [0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL, 0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL, 0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL, 0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL];

private static immutable uint[24] keccakf_rotc = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

private static immutable uint[24] keccakf_piln = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

/*
 * generally called after SHA3_KECCAK_SPONGE_WORDS-ctx.capacityWords words
 * are XORed into the state s
 */
pure nothrow @safe @nogc @live
private void keccakf(ref ulong[25] s)

	do
	{
		enum KECCAK_ROUNDS = 24;
		ulong t = void;
		ulong[5] bc = void;

		for (size_t round = 0; round < KECCAK_ROUNDS; round++) {
			/* Theta */
			for (size_t i = 0; i < 5; i++) {
				bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
			}

			for (size_t i = 0; i < 5; i++) {
				t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);

				for (size_t j = 0; j < 25; j += 5) {
					s[j + i] ^= t;
				}
			}

			/* Rho Pi */
			t = s[1];

			for (size_t i = 0; i < 24; i++) {
				size_t j = keccakf_piln[i];
				bc[0] = s[j];
				s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
				t = bc[0];
			}

			/* Chi */
			for (size_t j = 0; j < 25; j += 5) {
				for (size_t i = 0; i < 5; i++) {
					bc[i] = s[j + i];
				}

				for (size_t i = 0; i < 5; i++) {
					s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
				}
			}

			/* Iota */
			s[0] ^= keccakf_rndc[round];
		}
	}

/* *************************** Public Inteface ************************ */

/* For Init or Reset call these: */
///
extern (C)
pure nothrow @trusted @nogc @live
public .sha3_return_t sha3_Init(scope void* priv, uint bitSize)

	in
	{
		assert(priv != null);
	}

	do
	{
		.sha3_context* ctx = cast(.sha3_context*)(priv);

		if ((bitSize != 256) && (bitSize != 384) && (bitSize != 512)) {
			return .SHA3_RETURN.SHA3_RETURN_BAD_PARAMS;
		}

		*ctx = (*ctx).init;
		ctx.capacityWords = 2 * bitSize / (8 * ulong.sizeof);

		return .SHA3_RETURN.SHA3_RETURN_OK;
	}

///
extern (C)
pure nothrow @trusted @nogc @live
public void sha3_Init256(scope void* priv)

	do
	{
		.sha3_Init(priv, 256);
	}

///
extern (C)
pure nothrow @trusted @nogc @live
public void sha3_Init384(scope void* priv)

	do
	{
		.sha3_Init(priv, 384);
	}

///
extern (C)
pure nothrow @trusted @nogc @live
public void sha3_Init512(scope void* priv)

	do
	{
		.sha3_Init(priv, 512);
	}

///
extern (C)
pure nothrow @trusted @nogc @live
public .SHA3_FLAGS sha3_SetFlags(scope void* priv, .SHA3_FLAGS flags)

	in
	{
		assert(priv != null);
	}

	do
	{
		.sha3_context* ctx = cast(.sha3_context*)(priv);
		flags &= .SHA3_FLAGS.SHA3_FLAGS_KECCAK;
		ctx.capacityWords |= (flags == .SHA3_FLAGS.SHA3_FLAGS_KECCAK) ? (SHA3_USE_KECCAK_FLAG) : (0);

		return flags;
	}

///
extern (C)
pure nothrow @trusted @nogc @live
public void sha3_Update(scope void* priv, scope const void* bufIn, size_t len)

	in
	{
		assert(priv != null);
		assert(bufIn != null);

		.sha3_context* ctx = cast(.sha3_context*)(priv);
		assert(ctx.byteIndex < 8);
		assert(ctx.wordIndex < (ctx.u.s.sizeof / ctx.u.s[0].sizeof));
	}

	do
	{
		.sha3_context* ctx = cast(.sha3_context*)(priv);

		/* 0...7 -- how much is needed to have a word */
		uint old_tail = (8 - ctx.byteIndex) & 7;

		const (ubyte)* buf = cast(const (ubyte)*)(bufIn);

		//SHA3_TRACE_BUF("called to update with:", buf, len);

		if (len < old_tail) {
			/*
			 * have no complete word or haven't started
			 * the word yet
			 */
			//SHA3_TRACE("because %d<%d, store it and return", cast(uint)(len), cast(uint)(old_tail));

			/* endian-independent code follows: */
			while (len--) {
				ctx.saved |= cast(ulong)(*(buf++)) << ((ctx.byteIndex++) * 8);
			}

			assert(ctx.byteIndex < 8);

			return;
		}

		if (old_tail != 0) { /* will have one word to process */
			//SHA3_TRACE("completing one word with %d bytes", cast(uint)(old_tail));
			/* endian-independent code follows: */
			len -= old_tail;

			while (old_tail--) {
				ctx.saved |= cast(ulong)(*(buf++)) << ((ctx.byteIndex++) * 8);
			}

			/* now ready to add saved to the sponge */
			ctx.u.s[ctx.wordIndex] ^= ctx.saved;
			assert(ctx.byteIndex == 8);
			ctx.byteIndex = 0;
			ctx.saved = 0;

			if (++ctx.wordIndex == (.SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx.capacityWords))) {
				keccakf(ctx.u.s);
				ctx.wordIndex = 0;
			}
		}

		/* now work in full words directly from input */

		assert(ctx.byteIndex == 0);

		size_t words = len / ulong.sizeof;
		uint tail = cast(uint)(len - (words * ulong.sizeof));

		//SHA3_TRACE("have %d full words to process", cast(uint)(words));

		for (size_t i = 0; i < words; i++, buf += ulong.sizeof) {
			const ulong t = cast(ulong)(buf[0]) | (cast(ulong)(buf[1]) << (8 * 1)) | (cast(ulong)(buf[2]) << (8 * 2)) | (cast(ulong)(buf[3]) << (8 * 3)) | (cast(ulong)(buf[4]) << (8 * 4)) | (cast(ulong)(buf[5]) << (8 * 5)) | (cast(ulong)(buf[6]) << (8 * 6)) | (cast(ulong)(buf[7]) << (8 * 7));

			//#if defined(__x86_64__) || defined(__i386__)
			//	assert(core.stdc.string.memcmp(&t, buf, 8) == 0);
			//#endif

			ctx.u.s[ctx.wordIndex] ^= t;

			if (++ctx.wordIndex == (.SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx.capacityWords))) {
				keccakf(ctx.u.s);
				ctx.wordIndex = 0;
			}
		}

		//SHA3_TRACE("have %d bytes left to process, save them", cast(uint)(tail));

		/* finally, save the partial word */
		assert((ctx.byteIndex == 0) && (tail < 8));

		while (tail--) {
			//SHA3_TRACE("Store byte %02x '%c'", *buf, *buf);
			ctx.saved |= cast(ulong)(*(buf++)) << ((ctx.byteIndex++) * 8);
		}

		assert(ctx.byteIndex < 8);
		//SHA3_TRACE("Have saved=0x%016" PRIx64 " at the end", ctx.saved);
	}

/**
 * This is simply the 'update' with the padding block.
 * The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80
 * bytes are always present, but they can be the same byte.
 */
extern (C)
pure nothrow @trusted @nogc @live
public const (void)* sha3_Finalize(return scope void* priv)

	in
	{
		assert(priv != null);
	}

	do
	{
		.sha3_context* ctx = cast(.sha3_context*)(priv);

		//SHA3_TRACE("called with %d bytes in the buffer", ctx.byteIndex);

		/*
		 * Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
		 * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
		 * Overall, we feed 0, then 1, and finally 1 to start padding. Without
		 * M || 01, we would simply use 1 to start padding.
		 */

		ulong t = void;

		if (ctx.capacityWords & SHA3_USE_KECCAK_FLAG) {
			/* Keccak version */
			t = cast(ulong)((cast(ulong)(1)) << (ctx.byteIndex * 8));
		} else {
			/* SHA3 version */
			t = cast(ulong)((cast(ulong)(0x02 | (1 << 2))) << ((ctx.byteIndex) * 8));
		}

		ctx.u.s[ctx.wordIndex] ^= ctx.saved ^ t;

		ctx.u.s[cast(size_t)(.SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx.capacityWords) - 1)] ^= 0x8000000000000000UL;
		keccakf(ctx.u.s);

		/*
		 * Return first bytes of the ctx.s. This conversion is not needed for
		 * little-endian platforms e.g. wrap with #if !defined(__BYTE_ORDER__)
		 * || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__
		 *    ... the conversion below ...
		 * #endif
		 */
		{
			for (uint i = 0; i < .SHA3_KECCAK_SPONGE_WORDS; i++) {
				const uint t1 = cast(uint)(ctx.u.s[i]);
				const uint t2 = cast(uint)((ctx.u.s[i] >> 16) >> 16);
				ctx.u.sb[(i * 8) + 0] = cast(ubyte)(t1);
				ctx.u.sb[(i * 8) + 1] = cast(ubyte)(t1 >> 8);
				ctx.u.sb[(i * 8) + 2] = cast(ubyte)(t1 >> 16);
				ctx.u.sb[(i * 8) + 3] = cast(ubyte)(t1 >> 24);
				ctx.u.sb[(i * 8) + 4] = cast(ubyte)(t2);
				ctx.u.sb[(i * 8) + 5] = cast(ubyte)(t2 >> 8);
				ctx.u.sb[(i * 8) + 6] = cast(ubyte)(t2 >> 16);
				ctx.u.sb[(i * 8) + 7] = cast(ubyte)(t2 >> 24);
			}
		}

		//SHA3_TRACE_BUF("Hash: (first 32 bytes)", ctx.u.sb, 256 / 8);

		return &(ctx.u.sb[0]);
	}



/* Single-call hashing */
/**
 * ?
 *
 * Params:
 *      bitSize = 256, 384, 512
 *      flags = .SHA3_FLAGS.SHA3_FLAGS_NONE or .SHA3_FLAGS.SHA3_FLAGS_KECCAK
 *      in_ = ?
 *      inBytes = ?
 *      out_ = ?
 *      outBytes = up to bitSize / 8; truncation OK
 *
 * Returns: ?
 */
extern (C)
pure nothrow @trusted @nogc @live
public .sha3_return_t sha3_HashBuffer(uint bitSize, .SHA3_FLAGS flags, scope const void* in_, size_t inBytes, return scope void* out_, uint outBytes)

	in
	{
		assert(in_ != null);
		assert(out_ != null);
	}

	do
	{
		.sha3_context c = void;
		.sha3_return_t err = .sha3_Init(&c, bitSize);

		if (err != .SHA3_RETURN.SHA3_RETURN_OK) {
			return err;
		}

		if (.sha3_SetFlags(&c, flags) != flags) {
			return .SHA3_RETURN.SHA3_RETURN_BAD_PARAMS;
		}

		.sha3_Update(&c, in_, inBytes);
		const void* h = .sha3_Finalize(&c);
		uint out_length = bitSize / 8;

		if (outBytes < out_length) {
			return .SHA3_RETURN.SHA3_RETURN_BAD_PARAMS;
		}

		out_[0 .. out_length] = h[0 .. out_length];

		return .SHA3_RETURN.SHA3_RETURN_OK;
	}

/* *************************** Self Tests ************************ */

/*
 * There are two set of mutually exclusive tests, based on SHA3_USE_KECCAK,
 * which is undefined in the production version.
 *
 * Known answer tests are from NIST SHA3 test vectors at
 * http://csrc.nist.gov/groups/ST/toolkit/examples.html
 *
 * SHA3-256:
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_Msg0.pdf
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_1600.pdf
 * SHA3-384:
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-384_1600.pdf
 * SHA3-512:
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-512_1600.pdf
 *
 * These are refered to as [FIPS 202] tests.
 *
 * -----
 *
 * A few Keccak algorithm tests (when M and not M||01 is hashed) are
 * added here. These are from http://keccak.noekeon.org/KeccakKAT-3.zip,
 * ShortMsgKAT_256.txt for sizes even to 8. There is also one test for
 * ExtremelyLongMsgKAT_256.txt.
 *
 * These will work with this code when SHA3_USE_KECCAK converts Finalize
 * to use "pure" Keccak algorithm.
 *
 *
 * These are referred to as [Keccak] test.
 *
 * -----
 *
 * In one case the input from [Keccak] test was used to test SHA3
 * implementation. In this case the calculated hash was compared with
 * the output of the sha3sum on Fedora Core 20 (which is Perl's based).
 *
 */

version (SHA3IUF_D_ENABLE_UNITTEST)
unittest
{
	static import core.stdc.stdio;
	static import core.stdc.string;

	/* [FIPS 202] KAT follow */
	static immutable ubyte[256 / 8] sha3_256_empty = [0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66, 0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62, 0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA, 0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A];
	static immutable ubyte[256 / 8] sha3_256_0xa3_200_times = [0x79, 0xF3, 0x8A, 0xDE, 0xC5, 0xC2, 0x03, 0x07, 0xA9, 0x8E, 0xF7, 0x6E, 0x83, 0x24, 0xAF, 0xBF, 0xD4, 0x6C, 0xFD, 0x81, 0xB2, 0x2E, 0x39, 0x73, 0xC6, 0x5F, 0xA1, 0xBD, 0x9D, 0xE3, 0x17, 0x87];
	static immutable ubyte[384 / 8] sha3_384_0xa3_200_times = [0x18, 0x81, 0xDE, 0x2C, 0xA7, 0xE4, 0x1E, 0xF9, 0x5D, 0xC4, 0x73, 0x2B, 0x8F, 0x5F, 0x00, 0x2B, 0x18, 0x9C, 0xC1, 0xE4, 0x2B, 0x74, 0x16, 0x8E, 0xD1, 0x73, 0x26, 0x49, 0xCE, 0x1D, 0xBC, 0xDD, 0x76, 0x19, 0x7A, 0x31, 0xFD, 0x55, 0xEE, 0x98, 0x9F, 0x2D, 0x70, 0x50, 0xDD, 0x47, 0x3E, 0x8F];
	static immutable ubyte[512 / 8] sha3_512_0xa3_200_times = [0xE7, 0x6D, 0xFA, 0xD2, 0x20, 0x84, 0xA8, 0xB1, 0x46, 0x7F, 0xCF, 0x2F, 0xFA, 0x58, 0x36, 0x1B, 0xEC, 0x76, 0x28, 0xED, 0xF5, 0xF3, 0xFD, 0xC0, 0xE4, 0x80, 0x5D, 0xC4, 0x8C, 0xAE, 0xEC, 0xA8, 0x1B, 0x7C, 0x13, 0xC3, 0x0A, 0xDF, 0x52, 0xA3, 0x65, 0x95, 0x84, 0x73, 0x9A, 0x2D, 0xF4, 0x6B, 0xE5, 0x89, 0xC5, 0x1C, 0xA1, 0xA4, 0xA8, 0x41, 0x6D, 0xF6, 0x54, 0x5A, 0x1C, 0xE8, 0xBA, 0x00];

	/* ---- "pure" Keccak algorithm begins; from [Keccak] ----- */

	ubyte[200] buf = void;
	.sha3_HashBuffer(256, .SHA3_FLAGS.SHA3_FLAGS_KECCAK, &("abc\0"[0]), 3, &(buf[0]), buf.length);

	assert(core.stdc.string.memcmp(&(buf[0]), &("\x4e\x03\x65\x7a\xea\x45\xa9\x4f\xc7\xd4\x7b\xa8\x26\xc8\xd6\x67\xc0\xd1\xe6\xe3\x3a\x64\xa0\x36\xec\x44\xf5\x8f\xa1\x2d\x6c\x45\0"[0]), 256 / 8) == 0, "SHA3-256(abc) doesn't match known answer (single buffer)\n");

	.sha3_context c = void;
	const (ubyte)* hash = void;

	{
		.sha3_Init256(&c);
		.sha3_SetFlags(&c, .SHA3_FLAGS.SHA3_FLAGS_KECCAK);
		.sha3_Update(&c, &("\xcc\0"[0]), 1);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(hash, &("\xee\xad\x6d\xbf\xc7\x34\x0a\x56\xca\xed\xc0\x44\x69\x6a\x16\x88\x70\x54\x9a\x6a\x7f\x6f\x56\x96\x1e\x84\xa5\x4b\xd9\x97\x0b\x8a\0"[0]), 256 / 8) == 0, "SHA3-256(cc) doesn't match known answer (single buffer)\n");
	}

	{
		.sha3_Init256(&c);
		.sha3_SetFlags(&c, .SHA3_FLAGS.SHA3_FLAGS_KECCAK);
		.sha3_Update(&c, &("\x41\xfb\0"[0]), 2);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(hash, &("\xa8\xea\xce\xda\x4d\x47\xb3\x28\x1a\x79\x5a\xd9\xe1\xea\x21\x22\xb4\x07\xba\xf9\xaa\xbc\xb9\xe1\x8b\x57\x17\xb7\x87\x35\x37\xd2\0"[0]), 256 / 8) == 0, "SHA3-256(41fb) doesn't match known answer (single buffer)\n");
	}

	{
		.sha3_Init256(&c);
		.sha3_SetFlags(&c, .SHA3_FLAGS.SHA3_FLAGS_KECCAK);
		.sha3_Update(&c, &("\x52\xa6\x08\xab\x21\xcc\xdd\x8a\x44\x57\xa5\x7e\xde\x78\x21\x76\0"[0]), 128 / 8);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(hash, &("\x0e\x32\xde\xfa\x20\x71\xf0\xb5\xac\x0e\x6a\x10\x8b\x84\x2e\xd0\xf1\xd3\x24\x97\x12\xf5\x8e\xe0\xdd\xf9\x56\xfe\x33\x2a\x5f\x95\0"[0]), 256 / 8) == 0, "SHA3-256(52a6...76) doesn't match known answer (single buffer)\n");
	}

	{
		.sha3_Init256(&c);
		.sha3_SetFlags(&c, .SHA3_FLAGS.SHA3_FLAGS_KECCAK);
		.sha3_Update(&c, &("\x43\x3c\x53\x03\x13\x16\x24\xc0\x02\x1d\x86\x8a\x30\x82\x54\x75\xe8\xd0\xbd\x30\x52\xa0\x22\x18\x03\x98\xf4\xca\x44\x23\xb9\x82\x14\xb6\xbe\xaa\xc2\x1c\x88\x07\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0\x92\xcc\x1b\x06\xce\xdf\x32\x24\xd5\xed\x1e\xc2\x97\x84\x44\x4f\x22\xe0\x8a\x55\xaa\x58\x54\x2b\x52\x4b\x02\xcd\x3d\x5d\x5f\x69\x07\xaf\xe7\x1c\x5d\x74\x62\x22\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84\x6d\xcb\xb4\xce\0"[0]), 800 / 8);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(hash, &("\xce\x87\xa5\x17\x3b\xff\xd9\x23\x99\x22\x16\x58\xf8\x01\xd4\x5c\x29\x4d\x90\x06\xee\x9f\x3f\x9d\x41\x9c\x8d\x42\x77\x48\xdc\x41\0"[0]), 256 / 8) == 0, "SHA3-256(433C...CE) doesn't match known answer (single buffer)\n");
	}

	/*
	 * SHA3-256 byte-by-byte: 16777216 steps. ExtremelyLongMsgKAT_256
	 * [Keccak]
	 */
	version (SHA3IUF_D_ALL_UNITTEST) {
		{
			uint i = 16777216;
			.sha3_Init256(&c);
			.sha3_SetFlags(&c, .SHA3_FLAGS.SHA3_FLAGS_KECCAK);

			while (i--) {
				core.stdc.stdio.printf("%u\n", i);
				.sha3_Update(&c, &("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\0"[0]), 64);
			}

			hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

			assert(core.stdc.string.memcmp(hash, &("\x5f\x31\x3c\x39\x96\x3d\xcf\x79\x2b\x54\x70\xd4\xad\xe9\xf3\xa3\x56\xa3\xe4\x02\x17\x48\x69\x0a\x95\x83\x72\xe2\xb0\x6f\x82\xa4\0"[0]), 256 / 8) == 0, "SHA3-256( abcdefgh...[16777216 times] ) doesn't match known answer\n");

			core.stdc.stdio.printf("Keccak-256 tests passed OK\n");
		}
	}

	/* ----- SHA3 testing begins ----- */

	/* SHA-256 on an empty buffer */
	{
		.sha3_Init256(&c);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_256_empty[0]), hash, sha3_256_empty.length) == 0, "SHA3-256() doesn't match known answer\n");

		.sha3_HashBuffer(256, .SHA3_FLAGS.SHA3_FLAGS_NONE, &("abc\0"[0]), 3, &(buf[0]), buf.length);

		assert(core.stdc.string.memcmp(&(buf[0]), &("\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32\0"[0]), 256 / 8) == 0, "SHA3-256(abc) doesn't match known answer (single buffer)\n");
	}

	/* set to value c1 */
	const ubyte c1 = 0xA3;
	buf[] = c1;

	/* SHA3-256 as a single buffer. [FIPS 202] */
	{
		.sha3_Init256(&c);
		.sha3_Update(&c, &(buf[0]), buf.length);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_256_0xa3_200_times[0]), hash, sha3_256_0xa3_200_times.length) == 0, "SHA3-256( 0xA3 ... [200 times] ) doesn't match known answer (1 buffer)\n");
	}

	/* SHA3-256 in two steps. [FIPS 202] */
	{
		.sha3_Init256(&c);
		.sha3_Update(&c, &(buf[0]), buf.length / 2);
		.sha3_Update(&c, &(buf[0]) + (buf.length / 2), buf.length / 2);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_256_0xa3_200_times[0]), hash, sha3_256_0xa3_200_times.length) == 0, "SHA3-256( 0xA3 ... [200 times] ) doesn't match known answer (2 steps)\n");
	}

	/* SHA3-256 byte-by-byte: 200 steps. [FIPS 202] */
	{
		uint i = 200;
		.sha3_Init256(&c);

		while (i--) {
			.sha3_Update(&c, &c1, 1);
		}

		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_256_0xa3_200_times[0]), hash, sha3_256_0xa3_200_times.length) == 0, "SHA3-256( 0xA3 ... [200 times] ) doesn't match known answer (200 steps)\n");
	}

	/*
	 * SHA3-256 byte-by-byte: 135 bytes. Input from [Keccak]. Output
	 * matched with sha3sum.
	 */
	{
		.sha3_Init256(&c);
		.sha3_Update(&c, &("\xb7\x71\xd5\xce\xf5\xd1\xa4\x1a\x93\xd1\x56\x43\xd7\x18\x1d\x2a\x2e\xf0\xa8\xe8\x4d\x91\x81\x2f\x20\xed\x21\xf1\x47\xbe\xf7\x32\xbf\x3a\x60\xef\x40\x67\xc3\x73\x4b\x85\xbc\x8c\xd4\x71\x78\x0f\x10\xdc\x9e\x82\x91\xb5\x83\x39\xa6\x77\xb9\x60\x21\x8f\x71\xe7\x93\xf2\x79\x7a\xea\x34\x94\x06\x51\x28\x29\x06\x5d\x37\xbb\x55\xea\x79\x6f\xa4\xf5\x6f\xd8\x89\x6b\x49\xb2\xcd\x19\xb4\x32\x15\xad\x96\x7c\x71\x2b\x24\xe5\x03\x2d\x06\x52\x32\xe0\x2c\x12\x74\x09\xd2\xed\x41\x46\xb9\xd7\x5d\x76\x3d\x52\xdb\x98\xd9\x49\xd3\xb0\xfe\xd6\xa8\x05\x2f\xbb\0"[0]), 1080 / 8);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(hash, &("\xa1\x9e\xee\x92\xbb\x20\x97\xb6\x4e\x82\x3d\x59\x77\x98\xaa\x18\xbe\x9b\x7c\x73\x6b\x80\x59\xab\xfd\x67\x79\xac\x35\xac\x81\xb5\0"[0]), 256 / 8) == 0, "SHA3-256( b771 ... ) doesn't match the known answer\n");
	}

	/* SHA3-384 as a single buffer. [FIPS 202] */
	{
		.sha3_Init384(&c);
		.sha3_Update(&c, &(buf[0]), buf.length);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_384_0xa3_200_times[0]), hash, sha3_384_0xa3_200_times.length) == 0, "SHA3-384( 0xA3 ... [200 times] ) doesn't match known answer (1 buffer)\n");
	}

	/* SHA3-384 in two steps. [FIPS 202] */
	{
		.sha3_Init384(&c);
		.sha3_Update(&c, &(buf[0]), buf.length / 2);
		.sha3_Update(&c, &(buf[0]) + (buf.length / 2), buf.length / 2);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_384_0xa3_200_times[0]), hash, sha3_384_0xa3_200_times.length) == 0, "SHA3-384( 0xA3 ... [200 times] ) doesn't match known answer (2 steps)\n");
	}

	/* SHA3-384 byte-by-byte: 200 steps. [FIPS 202] */
	{
		uint i = 200;
		.sha3_Init384(&c);

		while (i--) {
			.sha3_Update(&c, &c1, 1);
		}

		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_384_0xa3_200_times[0]), hash, sha3_384_0xa3_200_times.length) == 0, "SHA3-384( 0xA3 ... [200 times] ) doesn't match known answer (200 steps)\n");
	}

	/* SHA3-512 as a single buffer. [FIPS 202] */
	{
		.sha3_Init512(&c);
		.sha3_Update(&c, &(buf[0]), buf.length);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_512_0xa3_200_times[0]), hash, sha3_512_0xa3_200_times.length) == 0, "SHA3-512( 0xA3 ... [200 times] ) doesn't match known answer (1 buffer)\n");
	}

	/* SHA3-512 in two steps. [FIPS 202] */
	{
		.sha3_Init512(&c);
		.sha3_Update(&c, &(buf[0]), buf.length / 2);
		.sha3_Update(&c, &(buf[0]) + (buf.length / 2), buf.length / 2);
		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_512_0xa3_200_times[0]), hash, sha3_512_0xa3_200_times.length) == 0, "SHA3-512( 0xA3 ... [200 times] ) doesn't match known answer (2 steps)\n");
	}

	/* SHA3-512 byte-by-byte: 200 steps. [FIPS 202] */
	{
		uint i = 200;
		.sha3_Init512(&c);

		while (i--) {
			.sha3_Update(&c, &c1, 1);
		}

		hash = cast(const (ubyte)*)(.sha3_Finalize(&c));

		assert(core.stdc.string.memcmp(&(sha3_512_0xa3_200_times[0]), hash, sha3_512_0xa3_200_times.length) == 0, "SHA3-512( 0xA3 ... [200 times] ) doesn't match known answer (200 steps)\n");
	}

	core.stdc.stdio.printf("SHA3-256, SHA3-384, SHA3-512 tests passed OK\n");
}
