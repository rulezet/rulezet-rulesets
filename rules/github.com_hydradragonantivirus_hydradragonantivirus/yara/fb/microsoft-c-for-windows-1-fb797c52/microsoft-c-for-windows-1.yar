import "pe"
rule _Microsoft_C_for_Windows_1_
{
	meta:
		description = "Microsoft C for Windows (1)"
	strings:
		$0 = {33 ED 55 9A ?? ?? ?? ?? 0B C0 74}
	condition:
		$0 at pe.entry_point
}