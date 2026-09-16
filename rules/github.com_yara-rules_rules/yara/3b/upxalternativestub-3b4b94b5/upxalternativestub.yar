import "pe"
rule UPXAlternativestub
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

condition:
		$a0 at pe.entry_point
}