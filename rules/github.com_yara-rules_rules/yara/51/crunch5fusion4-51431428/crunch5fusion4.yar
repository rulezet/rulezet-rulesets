rule Crunch5Fusion4
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 15 03 [3] 06 [11] 68 [4] 55 E8 }

condition:
		$a0
}