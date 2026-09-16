rule Win_Trojan_Pentagon_2
{
strings:
	$a0 = { c88ed0bc00f08ed8fbbd447c817606 }


condition:
	$a0
}