import "pe"
rule _Spalsher_v10__v30_
{
	meta:
		description = "Spalsher v1.0 - v3.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 89 AD 8C 01 ?? ?? 8B C5 2B 85 FE 75 ?? ?? 89 85 3E}
	condition:
		$0 at pe.entry_point
}