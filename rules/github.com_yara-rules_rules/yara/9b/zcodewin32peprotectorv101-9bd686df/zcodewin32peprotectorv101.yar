import "pe"
rule ZCodeWin32PEProtectorv101
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 12 00 00 00 [12] E9 FB FF FF FF C3 68 [4] 64 FF 35 }

condition:
		$a0 at pe.entry_point
}