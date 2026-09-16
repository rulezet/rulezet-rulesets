import "pe"
rule APatchGUIv11
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF }

condition:
		$a0 at pe.entry_point
}