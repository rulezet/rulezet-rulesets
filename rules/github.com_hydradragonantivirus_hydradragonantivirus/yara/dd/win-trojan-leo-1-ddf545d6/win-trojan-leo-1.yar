rule Win_Trojan_Leo_1
{
strings:
	$a0 = { ad078bd583ea13cd21b8004233c933d2cd21b440b9 }


condition:
	$a0
}