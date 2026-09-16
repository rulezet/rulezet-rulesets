import "pe"
rule _Zortech_C_v30_
{
	meta:
		description = "Zortech C v3.0"
	strings:
		$0 = {FA FC B8 ?? ?? ?? 8C C8 8E D8}
	condition:
		$0 at pe.entry_point
}