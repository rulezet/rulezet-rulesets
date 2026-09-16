rule Win_Trojan_OneHalf_21
{
strings:
	$a0 = { fb80fc11740580fc12752feb00530650b42fe87ffc58e8 }


condition:
	$a0
}