rule Win_Trojan_DiskEraser_2
{
strings:
	$a0 = { 0106b8020033dbb9100033d2cd20ea0000ffff }


condition:
	$a0
}