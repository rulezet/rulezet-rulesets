import "pe"
rule DingBoysPElockPhantasmv08
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

condition:
		$a0 at pe.entry_point
}