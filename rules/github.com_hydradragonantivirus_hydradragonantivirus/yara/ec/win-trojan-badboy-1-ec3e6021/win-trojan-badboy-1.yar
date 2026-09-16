rule Win_Trojan_Badboy_1
{
strings:
	$a0 = { ff3627010e1f2eff262501 }


condition:
	$a0
}