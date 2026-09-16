rule Win_Trojan_Halloween_2
{
strings:
	$a0 = { e7c685602700833e603c1475e8c606623e008dbe00 }


condition:
	$a0
}