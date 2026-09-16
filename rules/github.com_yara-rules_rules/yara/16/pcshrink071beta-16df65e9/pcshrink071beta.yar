import "pe"
rule PCShrink071beta
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }

condition:
		$a0 at pe.entry_point
}