import "pe"
rule ASProtectV2XDLLAlexeySolodovnikov
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 03 00 00 00 E9 [2] 5D 45 55 C3 E8 01 00 00 00 EB 5D BB [4] 03 DD }

condition:
		$a0 at pe.entry_point
}