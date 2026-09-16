rule Win_Trojan_Diga_1
{
strings:
	$a0 = { 4ebadf01e84500721db8023dba9e00e83a0093b440b1fdba0001e82f00b43ee82a00b44febdeb42ae8 }


condition:
	$a0
}