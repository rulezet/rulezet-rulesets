rule Win_Trojan_Winlamer_1
{
strings:
	$a0 = { 82074109b1094bc428b34309b04909bd36c42888374309474c }


condition:
	$a0
}