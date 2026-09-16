import "pe"
rule PEncryptv31
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 [3] 00 F0 0F C6 }

condition:
		$a0 at pe.entry_point
}