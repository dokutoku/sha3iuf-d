module sha3iuf_d.wasm;


version (WebAssembly):

version (SHA3IUF_D_WASM)
extern (C)
pure nothrow @safe @nogc @live
export void _start()

	do
	{
	}

version (SHA3IUF_D_WASM)
extern (C)
pure nothrow @trusted @nogc @live
export void* memset(return ubyte* s, int c, size_t n)

	do
	{
		for (size_t i = 0; i < n; i++) {
			s[i] = cast(ubyte)(c);
		}

		return s;
	}

version (SHA3IUF_D_WASM)
extern (C)
pure nothrow @trusted @nogc @live
export void* memcpy(return ubyte* s1, scope const ubyte* s2, size_t n)

	do
	{
		for (size_t i = 0; i < n; i++) {
			s1[i] = s2[i];
		}

		return s1;
	}

version (SHA3IUF_D_ENABLE_STATIC_BUFFER) {
	enum input_buffer_length = 4096;
	enum output_buffer_length = 512 / 8;

	export ubyte[.input_buffer_length] input_buffer;
	export ubyte[.output_buffer_length] output_buffer;

	extern (C)
	pure nothrow @safe @nogc @live
	export size_t input_buf_length()

		do
		{
			return .input_buffer_length;
		}

	extern (C)
	pure nothrow @safe @nogc @live
	export size_t output_buf_length()

		do
		{
			return .output_buffer_length;
		}

	extern (C)
	nothrow @nogc @trusted @live
	export ubyte* get_input_buffer_address()

		do
		{
			return &(.input_buffer[0]);
		}

	extern (C)
	nothrow @nogc @trusted @live
	export ubyte* get_output_buffer_address()

		do
		{
			return &(.output_buffer[0]);
		}
}
