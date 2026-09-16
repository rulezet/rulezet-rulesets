rule Win_Trojan_Bishkek_3
{
strings:
	$a0 = { 72005589e5bf7c040e57bffe1f1e576a059a8e057200c606c80000c6060420006a00bffa1f1e576a029ad40a72 }


condition:
	$a0
}