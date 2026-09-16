import "pe"
rule PROPACKv208
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 8C D3 8E C3 8C CA 8E DA 8B 0E [2] 8B F1 83 [2] 8B FE D1 ?? FD F3 A5 53 }

condition:
		$a0 at pe.entry_point
}