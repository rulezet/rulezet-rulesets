import "pe"
rule wzip_sfx_6
{
	meta:
		author = "PEiD"
		description = "WinZip 32-bit SFX 6.x module"
		group = "190"
		function = "0"
	strings:
		$a0 = { FF 15 ?? ?? ?? ?? B1 22 38 08 74 02 B1 20 40 80 38 ?? 74 10 38 08 74 06 40 80 38 ?? 75 F6 80 38 ?? 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }
	condition:
		$a0 at pe.entry_point
}