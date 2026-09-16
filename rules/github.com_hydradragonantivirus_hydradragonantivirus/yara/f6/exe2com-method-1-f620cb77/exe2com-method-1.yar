import "pe"
rule _EXE2COM_Method_1_
{
	meta:
		description = "EXE2COM (Method 1)"
	strings:
		$0 = {8C DB BE ?? ?? 8B C6 B1 ?? D3 E8 03 C3 03 ?? ?? A3 ?? ?? 8C C8 05 ?? ?? A3}
	condition:
		$0 at pe.entry_point
}