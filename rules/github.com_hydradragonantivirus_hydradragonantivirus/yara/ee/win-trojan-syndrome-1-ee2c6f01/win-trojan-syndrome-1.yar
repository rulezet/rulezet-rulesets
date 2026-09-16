rule Win_Trojan_Syndrome_1
{
strings:
	$a0 = { 8b861f012e89860c018db63301b9ce022e8134 }


condition:
	$a0
}