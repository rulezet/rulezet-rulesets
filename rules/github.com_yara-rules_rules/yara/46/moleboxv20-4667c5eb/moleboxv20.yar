rule MoleBoxv20
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [4] 60 E8 4F }

condition:
		$a0
}