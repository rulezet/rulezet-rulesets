import "pe"
rule HACKSTOPv111c
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B4 30 CD 21 86 E0 3D [2] 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB [2] 5B EB }

condition:
		$a0 at pe.entry_point
}