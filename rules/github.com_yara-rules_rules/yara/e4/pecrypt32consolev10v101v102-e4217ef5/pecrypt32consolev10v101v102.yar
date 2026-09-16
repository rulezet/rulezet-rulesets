import "pe"
rule PECrypt32Consolev10v101v102
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

condition:
		$a0 at pe.entry_point
}