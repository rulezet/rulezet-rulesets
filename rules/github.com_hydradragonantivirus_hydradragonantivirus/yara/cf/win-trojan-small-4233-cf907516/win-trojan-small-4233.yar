rule Win_Trojan_Small_4233
{
strings:
	$a0 = { 56893424030c2483c40456562b }


condition:
	$a0
}