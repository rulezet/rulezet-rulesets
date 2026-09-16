rule Win_Trojan_TDSS_65
{
strings:
	$a0 = { 558bec565733f656[0-128]6a4d6a4d6a376a }


condition:
	$a0
}