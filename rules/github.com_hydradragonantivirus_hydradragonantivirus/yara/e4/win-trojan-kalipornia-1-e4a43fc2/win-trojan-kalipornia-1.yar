rule Win_Trojan_Kalipornia_1
{
strings:
	$a0 = { 0301b41a8d961402cd21b44e8d960e02cd217209e83f00b44fcd2173f7b404cd1a81fa1509741b80fe097420b4 }


condition:
	$a0
}