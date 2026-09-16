rule Upx_12x
{
	meta:
		author = "PEiD"
		description = "Upx 1.24 - 1.25 -> Markus & Laszlo"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 83 F0 FF 74 78 D1 F8 89 C5 EB 0B 01 DB 75 07 }
	condition:
		$a0
}