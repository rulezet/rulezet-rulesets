import "pe"
rule upx062
{
	meta:
		author = "PEiD"
		description = "UPX 0.62 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}