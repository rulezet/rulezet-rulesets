import "pe"
rule DIETv100v100d
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BF [2] 3B FC 72 ?? B4 4C CD 21 BE [2] B9 [2] FD F3 A5 FC }

condition:
		$a0 at pe.entry_point
}