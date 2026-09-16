import "pe"
rule AdysGlue110
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 2E [4] 0E 1F BF [2] 33 DB 33 C0 AC }

condition:
		$a0 at pe.entry_point
}