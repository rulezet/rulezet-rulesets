import "pe"
rule EscargotV01Meat
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 }

condition:
		$a0 at pe.entry_point
}