import "pe"
rule UPXShit006mal
{
	meta:
		author="malware-lu"
strings:
		$a0 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

condition:
		$a0 at pe.entry_point
}