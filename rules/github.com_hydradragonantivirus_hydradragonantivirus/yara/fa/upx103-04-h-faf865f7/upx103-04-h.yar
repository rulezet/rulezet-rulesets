import "pe"
rule upx103_04_h
{
	meta:
		author = "PEiD"
		description = "UPX 1.03 - 1.04 modified -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
	condition:
		$a0 at pe.entry_point
}