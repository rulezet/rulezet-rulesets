import "pe"
rule _Unknown_packer_08_
{
	meta:
		description = "Unknown packer (08)"
	strings:
		$0 = {8B C4 2D ?? ?? 24 00 8B F8 57 B9 ?? ?? BE ?? ?? F3 A5 FD C3 97 4F 4F}
	condition:
		$0 at pe.entry_point
}