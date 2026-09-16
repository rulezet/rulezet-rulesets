import "pe"
rule BJFntv13
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB ?? 3A [2] 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

condition:
		$a0 at pe.entry_point
}