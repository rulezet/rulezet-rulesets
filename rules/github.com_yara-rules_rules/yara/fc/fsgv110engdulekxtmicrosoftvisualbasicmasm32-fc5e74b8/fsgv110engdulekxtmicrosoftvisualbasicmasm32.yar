import "pe"
rule FSGv110EngdulekxtMicrosoftVisualBasicMASM32
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 02 09 94 0F B7 FF 68 80 [2] 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

condition:
		$a0 at pe.entry_point
}