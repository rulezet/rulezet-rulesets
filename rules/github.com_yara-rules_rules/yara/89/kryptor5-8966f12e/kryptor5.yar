import "pe"
rule kryptor5
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 03 [3] E9 EB 6C 58 40 FF E0 }

condition:
		$a0 at pe.entry_point
}