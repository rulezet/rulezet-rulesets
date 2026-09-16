rule Win_Trojan_Leprosy_54
{
strings:
	$a0 = { b930158a273226??01882743e2f5c3 }


condition:
	$a0
}