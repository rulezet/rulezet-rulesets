rule Win_Trojan_Iraqui_1
{
strings:
	$a0 = { 0190b90300f3a4908bf2b43090cd }


condition:
	$a0
}