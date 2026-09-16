rule Win_Trojan_Agent_35467
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d }

	$a1 = { 7879332e444c4c }

	$a2 = { 4c49554c49414e47 }

	$a3 = { 5c69642e696e69 }


condition:
	$a0 and $a1 and $a2 and $a3
}