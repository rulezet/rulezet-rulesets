rule Win_Trojan_Gula_7
{
strings:
	$a0 = { 21b440b95c028bd583ea09cd21b8004233c933d2cd21b91800b4408bd6cd21b43ecd21b8014359 }


condition:
	$a0
}