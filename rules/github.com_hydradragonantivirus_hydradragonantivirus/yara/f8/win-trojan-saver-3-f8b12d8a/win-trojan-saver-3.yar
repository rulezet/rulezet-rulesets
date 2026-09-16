rule Win_Trojan_Saver_3
{
strings:
	$a0 = { 010100550005000000010016030000e9010000040000001703 }


condition:
	$a0
}