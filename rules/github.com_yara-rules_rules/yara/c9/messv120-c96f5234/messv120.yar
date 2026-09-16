import "pe"
rule MESSv120
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FA B9 [2] F3 [2] E3 ?? EB ?? EB ?? B6 }

condition:
		$a0 at pe.entry_point
}