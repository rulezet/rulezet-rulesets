rule Win_Trojan_BNB_3
{
strings:
	$a0 = { 83c619bf0001b90300f3a48bf2b82435cd210653b8 }


condition:
	$a0
}