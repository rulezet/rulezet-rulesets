rule _PeStubOEP_v1x_
{
	meta:
		description = "PeStubOEP v1.x"
	strings:
		$0 = {90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF}
		$1 = {E8 05 00 00 00 33 C0 40 48 C3 E8 05}
	condition:
		$0 or $1
}