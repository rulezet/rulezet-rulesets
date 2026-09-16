rule RpolycryptbyVaska2003071841
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 58 [7] E8 00 00 00 58 E8 00 [45] 00 00 00 [2] 04 }

condition:
		$a0
}