rule Win_Trojan_Waledac_8
{
strings:
	$a0 = { 558bec83ec5056ff15641040008bf08a063c2275 }

	$a1 = { 037275733b }

	$a2 = { 62006a006e006a007100330032002e006500780065 }


condition:
	$a0 and $a1 and $a2
}