import "pe"
rule FSGv110EngdulekxtMicrosoftVisualC5060
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 [3] EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }

condition:
		$a0 at pe.entry_point
}