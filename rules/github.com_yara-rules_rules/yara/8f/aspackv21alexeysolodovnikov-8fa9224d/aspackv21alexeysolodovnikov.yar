import "pe"
rule ASPackv21AlexeySolodovnikov
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

condition:
		$a0 at pe.entry_point
}