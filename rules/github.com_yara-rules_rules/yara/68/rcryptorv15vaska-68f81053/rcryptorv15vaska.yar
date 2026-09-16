import "pe"
rule RCryptorv15Vaska
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 2C 24 4F 68 [4] FF 54 24 04 83 44 24 04 4F }

condition:
		$a0 at pe.entry_point
}