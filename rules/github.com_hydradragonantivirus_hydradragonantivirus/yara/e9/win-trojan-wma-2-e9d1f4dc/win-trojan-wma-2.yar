rule Win_Trojan_WMA_2
{
strings:
	$a0 = { ba8000cd1326813fe8007412b801035041cd13b9c301902ef3a45841cd13b8010241cd13c3 }


condition:
	$a0
}