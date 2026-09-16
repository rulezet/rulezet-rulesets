rule Win_Trojan_DiskKiller_2
{
strings:
	$a0 = { 51b001e89c00597308b400cd13e2 }


condition:
	$a0
}