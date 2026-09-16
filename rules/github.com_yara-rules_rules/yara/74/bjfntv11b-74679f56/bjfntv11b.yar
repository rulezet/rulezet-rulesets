import "pe"
rule BJFntv11b
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }

condition:
		$a0 at pe.entry_point
}