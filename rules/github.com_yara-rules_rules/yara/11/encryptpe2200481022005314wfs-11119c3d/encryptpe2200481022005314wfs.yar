import "pe"
rule EncryptPE2200481022005314WFS
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A }

condition:
		$a0 at pe.entry_point
}