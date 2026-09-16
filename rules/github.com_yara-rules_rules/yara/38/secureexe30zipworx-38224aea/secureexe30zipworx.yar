import "pe"
rule SecureEXE30ZipWorx
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 B8 00 00 00 [3] 00 [3] 00 [3] 00 00 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}