import "pe"
rule _Unknown_Protected_Mode_compiler_2_
{
	meta:
		description = "Unknown Protected Mode compiler (2)"
	strings:
		$0 = {FA FC 0E 1F E8 ?? ?? 8C C0 66 0F B7 C0 66 C1 E0 ?? 66 67 A3}
	condition:
		$0 at pe.entry_point
}