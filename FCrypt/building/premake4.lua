solution "FCrypt"
	configurations {
		"Release-Dynamic", "Release-Dynamic-Module", "Release-Static", "Release-Static-Module",
		"Debug-Dynamic", "Debug-Dynamic-Module", "Debug-Static", "Debug-Static-Module"
	}

	project "FCrypt"
		language "C"
		flags {"ExtraWarnings"}
		files {"../sources/**.c"}
		includedirs {"../API"}
		--buildoptions {"-std=c89 -pedantic -Wall -Weverything"}

		configuration "Release*"
			targetdir "lib/release"

		configuration "Debug*"
			flags {"Symbols"}
			targetdir "lib/debug"

		configuration "*Dynamic*"
			kind "SharedLib"

		configuration "*Dynamic-Module"
			defines {"CIPHER_F_CRYPT_BUILD_MODULE_ABI"}
			targetprefix ""
			targetextension ".Cipher"

		configuration "*Static*"
			kind "StaticLib"
			defines {"CIPHER_F_CRYPT_STATIC"}

		configuration "*Static-Module"
			defines {"CIPHER_F_CRYPT_BUILD_ABI"}
