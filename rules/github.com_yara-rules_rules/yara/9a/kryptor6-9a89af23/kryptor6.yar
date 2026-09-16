import "pe"
rule kryptor6
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 03 [3] E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

condition:
		$a0 at pe.entry_point
}