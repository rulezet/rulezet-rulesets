import "pe"
rule EmbedPEv124cyclotron
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 EC 50 60 68 [4] E8 CB FF 00 00 }

condition:
		$a0 at pe.entry_point
}