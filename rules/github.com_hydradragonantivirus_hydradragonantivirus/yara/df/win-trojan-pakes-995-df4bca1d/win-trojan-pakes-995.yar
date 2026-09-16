rule Win_Trojan_Pakes_995
{
strings:
	$a0 = { 606a006a00e80c0000006465736b6164702e646c }


condition:
	$a0
}