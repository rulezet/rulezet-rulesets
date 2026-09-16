import "pe"
rule _Spalsher_10__30__Amok_
{
	meta:
		description = "Spalsher 1.0 - 3.0 -> Amok"
	strings:
		$0 = {31 ED 9A ?? ?? ?? ?? 55 89 E5 81 EC ?? ?? B8 ?? ?? 0E 50 9A ?? ?? ?? ?? BE ?? ?? 1E 0E BF ?? ?? 1E 07 1F FC}
		$1 = {9C 60 8B 44 24 24 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}