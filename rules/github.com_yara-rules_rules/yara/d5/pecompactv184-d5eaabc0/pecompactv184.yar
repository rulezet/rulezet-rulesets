import "pe"
rule PECompactv184
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

condition:
		$a0 at pe.entry_point
}