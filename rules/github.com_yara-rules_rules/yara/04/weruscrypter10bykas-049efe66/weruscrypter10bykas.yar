import "pe"
rule WerusCrypter10byKas
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

condition:
		$a0 at pe.entry_point
}