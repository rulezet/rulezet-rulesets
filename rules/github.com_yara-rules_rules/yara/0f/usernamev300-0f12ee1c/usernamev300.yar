import "pe"
rule USERNAMEv300
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FB 2E [4] 2E [4] 2E [4] 2E [4] 8C C8 2B C1 8B C8 2E [4] 2E [4] 33 C0 8E D8 06 0E 07 FC 33 F6 }

condition:
		$a0 at pe.entry_point
}