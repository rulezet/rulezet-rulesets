rule DestructiveTargetCleaningTool5
{
	strings:
		$MCU_DLL_ZLIB_COMPRESSED2 = { 5C EC AB AE 81 3C C9 BC D5 A5 42 F4 54 91 04 28 34 34 79 80 6F 71 D5 52 1E 2A 0D }
	
	condition:
		$MCU_DLL_ZLIB_COMPRESSED2
}