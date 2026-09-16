import "pe"
rule FSGv133
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }

condition:
		$a0 at pe.entry_point
}