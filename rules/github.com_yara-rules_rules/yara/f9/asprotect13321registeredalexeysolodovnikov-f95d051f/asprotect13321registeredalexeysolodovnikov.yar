import "pe"
rule ASProtect13321RegisteredAlexeySolodovnikov
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 01 [3] E8 01 00 00 00 C3 C3 }

condition:
		$a0 at pe.entry_point
}