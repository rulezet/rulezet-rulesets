rule Win_Trojan_Erase26_5
{
strings:
	$a0 = { 8ccb8edbbb0c01eb05ffffffff90b002cd26b001cd26b003cd26ea0000ffff90cd26 }


condition:
	$a0
}