/*
 * -------------------------------------------------------------------------
 * Run SHA-3 (NIST FIPS 202) on the given file.
 *
 * Call as
 *
 * sha3sum 256|384|512 file_path
 *
 * See sha3.c for additional details.
 *
 * Jun 2018. Andrey Jivsov. crypto@brainhub.org
 * ----------------------------------------------------------------------
 */
module sha3sum;


private static import core.stdc.stdio;
private static import core.stdc.stdlib;
private static import core.stdc.string;
private static import core.stdc.wchar_;
private static import core.sys.posix.fcntl;
private static import core.sys.posix.sys.mman;
private static import core.sys.posix.sys.stat;
private static import core.sys.posix.unistd;
private static import sha3iuf_d;

nothrow @nogc @live
private void help(scope const char* argv0)

	do
	{
		core.stdc.stdio.printf("To call: %s 256|384|512 [-k] file_path.\n", argv0);
	}

pure nothrow @nogc @live
private void byte_to_hex(ubyte b, ref char[3] s)

	do
	{
		s[0] = '0';
		s[1] = '0';
		s[2] = '\0';
		uint i = 1;

		while (b != 0) {
			uint t = b & 0x0F;
			assert(i < 2);

			if (t < 10) {
				s[i] = cast(char)('0' + t);
			} else {
				s[i] = cast(char)('a' + t - 10);
			}

			i--;
			b >>= 4;
		}
	}

version (Posix)
extern (C)
nothrow @nogc @live
int main(int argc, char** argv)

	do
	{
		if ((argc != 3) && (argc != 4)) {
			.help(argv[0]);

			return 1;
		}

		int image_size = core.stdc.stdlib.atoi(argv[1]);

		switch (image_size) {
			case 256:
			case 384:
			case 512:
				break;

			default:
				.help(argv[0]);

				return 1;
		}

		const (char)* file_path = argv[2];
		bool use_keccak = false;

		if ((argc == 4) && (file_path[0] == '-') && (file_path[1] == 'k')) {
			use_keccak = true;
			file_path = argv[3];
		}

		if (core.sys.posix.unistd.access(file_path, core.sys.posix.unistd.R_OK) != 0) {
			core.stdc.stdio.printf("Cannot read file '%s'", file_path);

			return 2;
		}

		int fd = core.sys.posix.fcntl.open(file_path, core.sys.posix.fcntl.O_RDONLY);

		if (fd == -1) {
			core.stdc.stdio.printf("Cannot open file '%s' for reading", file_path);

			return 2;
		}

		core.sys.posix.sys.stat.stat_t st = void;
		uint i = core.sys.posix.sys.stat.fstat(fd, &st);

		if (i != 0) {
			core.sys.posix.unistd.close(fd);
			core.stdc.stdio.printf("Cannot determine the size of file '%s'", file_path);

			return 2;
		}

		void* p = core.sys.posix.sys.mman.mmap(null, st.st_size, core.sys.posix.sys.mman.PROT_READ, core.sys.posix.sys.mman.MAP_SHARED, fd, 0);
		core.sys.posix.unistd.close(fd);

		if (p == null) {
			core.stdc.stdio.printf("Cannot memory-map file '%s'", file_path);

			return 2;
		}

		sha3iuf_d.sha3_context c = void;

		switch (image_size) {
			case 256:
				sha3iuf_d.sha3_Init256(&c);

				break;

			case 384:
				sha3iuf_d.sha3_Init384(&c);

				break;

			case 512:
				sha3iuf_d.sha3_Init512(&c);

				break;

			default:
				assert(false);
		}

		if (use_keccak) {
			sha3iuf_d.SHA3_FLAGS flags2 = sha3iuf_d.sha3_SetFlags(&c, sha3iuf_d.SHA3_FLAGS.SHA3_FLAGS_KECCAK);

			if (flags2 != sha3iuf_d.SHA3_FLAGS.SHA3_FLAGS_KECCAK) {
				core.stdc.stdio.printf("Failed to set Keccak mode");

				return 2;
			}
		}

		sha3iuf_d.sha3_Update(&c, p, st.st_size);
		const ubyte* hash = cast(const ubyte*)(sha3iuf_d.sha3_Finalize(&c));

		core.sys.posix.sys.mman.munmap(p, st.st_size);

		for (i = 0; i < (image_size / 8); i++) {
			char[3] s = void;
			.byte_to_hex(hash[i], s);
			core.stdc.stdio.printf("%s", &(s[0]));
		}

		core.stdc.stdio.printf("  %s\n", file_path);

		return 0;
	}
