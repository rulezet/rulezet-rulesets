import "pe"
rule _Inno_Setup_Module_
{
	meta:
		description = "Inno Setup Module"
	strings:
		$0 = {49 6E 6E}
		$1 = {55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}