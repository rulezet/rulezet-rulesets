import "pe"
rule PCShrinkerv020
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 E8 01 [2] 60 01 AD B3 27 40 ?? 68 }

condition:
		$a0 at pe.entry_point
}