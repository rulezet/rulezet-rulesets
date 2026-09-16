rule Win_Trojan_Monkey_4
{
strings:
	$a0 = { 05c7075c00bbd304c7072a00b43bba4805cd21f7c501 }


condition:
	$a0
}