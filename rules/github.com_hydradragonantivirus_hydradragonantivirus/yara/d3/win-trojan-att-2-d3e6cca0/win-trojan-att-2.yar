rule Win_Trojan_ATT_2
{
strings:
	$a0 = { 83ee3a26803d60b195f3a474118ed8be8400a5a5c7 }


condition:
	$a0
}