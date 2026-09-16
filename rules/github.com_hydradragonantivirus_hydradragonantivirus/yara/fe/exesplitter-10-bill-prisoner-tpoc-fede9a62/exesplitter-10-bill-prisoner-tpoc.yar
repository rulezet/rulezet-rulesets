import "pe"
rule _ExeSplitter_10__Bill_Prisoner__TPOC_
{
	meta:
		description = "ExeSplitter 1.0 -> Bill Prisoner / TPOC"
	strings:
		$0 = {E9 ?? ?? ?? 00 4D 5A ?? 00 ?? 00 00 00 04 00 ?? 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}