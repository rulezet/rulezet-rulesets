rule MaskPE16yzkzero
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 36 81 2C 24 [3] 00 C3 60 }

condition:
		$a0
}