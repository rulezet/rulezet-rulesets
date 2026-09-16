import "pe"
rule _yzPack_10__UsAr_
{
	meta:
		description = "yzPack 1.0 -> UsAr"
	strings:
		$0 = {60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C}
	condition:
		$0 at pe.entry_point
}