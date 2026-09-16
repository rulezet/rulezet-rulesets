rule Win_Trojan_Tiger_2
{
strings:
	$a0 = { 0101005500000000000100b71c000016020000040000000103 }


condition:
	$a0
}