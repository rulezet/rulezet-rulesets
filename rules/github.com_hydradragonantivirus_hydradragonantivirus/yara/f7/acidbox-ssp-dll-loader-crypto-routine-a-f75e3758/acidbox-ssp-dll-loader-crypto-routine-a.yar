rule AcidBox_SSP_DLL_Loader_Crypto_Routine_A {
  meta:
    description = "Detects AcidBox SSP DLL loaders, based on a unique cryptography routine"
    author      = "BitsOfBinary"
    reference   = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
    reference   = "https://bitsofbinary.github.io/yara/2023/03/28/100daysofyara-day-87.html"
    hash        = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
    version     = "1.0"
    date        = "2023-03-28"
    DaysofYARA  = "87/100"

  strings:
                            $ = { 0f b6 04 32 33 c8 88 0c 3a 41 ff c0 44 89 44 24 04 }

  condition:
    any of them
}