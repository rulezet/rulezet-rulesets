import "pe"
rule UPXProtectorv10x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB EC [4] 8A 06 46 88 07 47 01 DB 75 07 }

condition:
		$a0 at pe.entry_point
}