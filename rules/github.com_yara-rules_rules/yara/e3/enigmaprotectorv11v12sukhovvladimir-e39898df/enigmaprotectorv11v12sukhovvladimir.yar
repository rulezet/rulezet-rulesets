import "pe"
rule ENIGMAProtectorV11V12SukhovVladimir
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }

condition:
		$a0 at pe.entry_point
}