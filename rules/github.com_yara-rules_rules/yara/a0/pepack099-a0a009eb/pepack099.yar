import "pe"
rule PEPACK099
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2 }

condition:
		$a0 at pe.entry_point
}