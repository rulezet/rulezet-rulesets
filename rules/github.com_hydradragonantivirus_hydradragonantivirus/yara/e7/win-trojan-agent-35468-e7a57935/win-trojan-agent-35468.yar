rule Win_Trojan_Agent_35468
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085 }

	$a1 = { 6468777a2e444c4c }

	$a2 = { 78796d61696e2e62696e }


condition:
	$a0 and $a1 and $a2
}