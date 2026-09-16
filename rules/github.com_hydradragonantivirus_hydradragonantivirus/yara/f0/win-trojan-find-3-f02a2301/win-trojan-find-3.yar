rule Win_Trojan_Find_3
{
strings:
	$a0 = { 5e83ee03b94001b2398cd3fa8bec0e178be683c4225832e232c2504444e2f6 }


condition:
	$a0
}