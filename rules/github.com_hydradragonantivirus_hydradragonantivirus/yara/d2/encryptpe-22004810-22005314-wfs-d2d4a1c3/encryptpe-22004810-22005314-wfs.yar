import "pe"
rule _EncryptPE_22004810__22005314__WFS_
{
	meta:
		description = "EncryptPE 2.2004.8.10 - 2.2005.3.14 -> WFS"
	strings:
		$0 = {60 9C 64 FF 35 00 00 00 00 E8 7A}
	condition:
		$0 at pe.entry_point
}