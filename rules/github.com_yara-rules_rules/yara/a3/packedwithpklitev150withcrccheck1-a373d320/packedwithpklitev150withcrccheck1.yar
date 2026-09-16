import "pe"
rule PackedwithPKLITEv150withCRCcheck1
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 1F B4 09 BA [2] CD 21 B8 [2] CD 21 }

condition:
		$a0 at pe.entry_point
}