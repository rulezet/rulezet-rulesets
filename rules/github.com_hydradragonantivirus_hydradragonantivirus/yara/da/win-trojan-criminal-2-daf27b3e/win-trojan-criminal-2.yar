rule Win_Trojan_Criminal_2
{
strings:
	$a0 = { 3c0b81e90501ba050101eae8cefdcd21 }


condition:
	$a0
}