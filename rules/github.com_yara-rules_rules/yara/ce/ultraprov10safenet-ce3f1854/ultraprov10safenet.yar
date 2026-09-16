import "pe"
rule UltraProV10SafeNet
{
      meta:
		author="malware-lu"
strings:
		$a0 = { A1 [4] 85 C0 0F 85 3B 06 00 00 55 56 C7 05 [4] 01 00 00 00 FF 15 }

condition:
		$a0 at pe.entry_point
}