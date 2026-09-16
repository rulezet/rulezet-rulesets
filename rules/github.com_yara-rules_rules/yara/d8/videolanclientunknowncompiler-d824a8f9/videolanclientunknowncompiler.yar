import "pe"
rule VideoLanClientUnknownCompiler
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 89 E5 83 EC 08 [15] FF FF [19] 00 [7] 00 }

condition:
		$a0 at pe.entry_point
}