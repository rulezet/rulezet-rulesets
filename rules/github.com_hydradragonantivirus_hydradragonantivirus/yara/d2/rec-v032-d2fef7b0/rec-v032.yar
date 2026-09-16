import "pe"
rule _REC_v032_
{
	meta:
		description = "REC v0.32"
	strings:
		$0 = {06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D}
	condition:
		$0 at pe.entry_point
}