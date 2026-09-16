rule MaskPEV20yzkzero
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }

condition:
		$a0
}