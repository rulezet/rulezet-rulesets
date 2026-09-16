rule Win_Trojan_Tanya_2
{
strings:
	$a0 = { e800005b83eb03b9d007be00000e1fb0d130401cc0c804fe }


condition:
	$a0
}