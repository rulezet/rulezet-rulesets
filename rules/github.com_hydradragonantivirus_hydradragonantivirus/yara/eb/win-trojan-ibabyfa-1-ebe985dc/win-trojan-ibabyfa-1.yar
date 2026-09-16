rule Win_Trojan_Ibabyfa_1
{
strings:
	$a0 = { 50686f746f5f5669657765725f31325f736f757468 }


condition:
	$a0
}