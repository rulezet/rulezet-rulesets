rule Win_Trojan_Burger_2
{
strings:
	$a0 = { b43fb9000590ba00f890cd21b43ecd21 }


condition:
	$a0
}