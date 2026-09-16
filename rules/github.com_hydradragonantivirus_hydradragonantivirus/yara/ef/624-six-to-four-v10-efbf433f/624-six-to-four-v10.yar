import "pe"
rule _624_Six_to_Four_v10_
{
	meta:
		description = "624 (Six to Four) v1.0"
	strings:
		$0 = {50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED}
	condition:
		$0 at pe.entry_point
}