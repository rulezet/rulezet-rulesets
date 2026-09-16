rule Win_Trojan_Waledac_7
{
strings:
	$a0 = { 558bec83ec5856ff15341040008bf08a063c2275 }

	$a1 = { e9454e50eb }

	$a2 = { 4d6f6e696b65 }

	$a3 = { 5a004c0041005800410045 }


condition:
	$a0 and $a1 and $a2 and $a3
}