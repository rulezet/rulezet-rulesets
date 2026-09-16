rule Win_Trojan_Descend_1
{
strings:
	$a0 = { 3fb90300ba3702e8a9feb002e8620089162502ba3702e89afeb9250290ba0600b440e88efe }


condition:
	$a0
}