import "pe"
rule MoleBoxV23XMoleStudiocom
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }

condition:
		$a0 at pe.entry_point
}