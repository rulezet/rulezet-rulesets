rule Win_Trojan_Wiper_2
{
strings:
	$a0 = { 68e8814000e88efdffff68dc814000e884fdffff68d4814000e87afdffff68cc814000e870fdffff68c0814000e866fdffff }


condition:
	$a0
}