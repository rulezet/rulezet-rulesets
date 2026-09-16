rule Win_Trojan_Small_4531
{
strings:
	$a0 = { bdf995400055b917a140008b11ffd201d5e84400000089e9 }


condition:
	$a0
}