rule Win_Trojan_KitG_1
{
strings:
	$a0 = { 80fcda7507909090b4049dcf3d004b744290909080fc }


condition:
	$a0
}