rule Win_Trojan_Stardot_1
{
strings:
	$a0 = { c402595833d2fec83c0075e31f0758fa2e8e162104 }


condition:
	$a0
}