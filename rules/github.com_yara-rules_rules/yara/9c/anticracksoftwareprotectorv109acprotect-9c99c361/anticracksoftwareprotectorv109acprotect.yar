import "pe"
rule AnticrackSoftwareProtectorv109ACProtect
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 [8] 00 00 [12] E8 01 00 00 00 ?? 83 04 24 06 C3 [5] 00 }

condition:
		$a0 at pe.entry_point
}