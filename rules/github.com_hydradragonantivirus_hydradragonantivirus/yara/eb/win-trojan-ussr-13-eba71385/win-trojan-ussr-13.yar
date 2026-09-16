rule Win_Trojan_USSR_13
{
strings:
	$a0 = { d783ea13b44ecd21eb0590b44fcd21 }


condition:
	$a0
}