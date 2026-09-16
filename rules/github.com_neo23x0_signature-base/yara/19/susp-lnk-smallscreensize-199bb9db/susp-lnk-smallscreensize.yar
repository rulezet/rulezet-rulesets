rule SUSP_LNK_SmallScreenSize {
	meta:
		author = "Greg Lesnewich"
		description = "check for LNKs that have a screen buffer size and WindowSize dimensions of 1x1"
		date = "2023-01-01"
		version = "1.0"
		DaysofYARA = "1/100"

		id = "6194a76b-36d6-51d1-8d53-2e11172e29d2"
	strings:
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}
																			condition:
		uint32be(0x0) == 0x4c000000 and all of them
}