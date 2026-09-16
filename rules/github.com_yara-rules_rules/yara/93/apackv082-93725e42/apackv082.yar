import "pe"
rule aPackv082
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 1E 06 8C CB BA [2] 03 DA 8D [3] FC 33 F6 33 FF 48 4B 8E C0 8E DB }

condition:
		$a0 at pe.entry_point
}