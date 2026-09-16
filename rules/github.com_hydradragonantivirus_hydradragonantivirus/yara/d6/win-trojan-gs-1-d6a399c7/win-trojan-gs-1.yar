rule Win_Trojan_GS_1
{
strings:
	$a0 = { 55b802429933c9cd212d0300a38001e89700b4408bcfba5a022bca51cd21b440b96a02ba6a03 }


condition:
	$a0
}