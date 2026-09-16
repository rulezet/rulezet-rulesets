rule Win_Trojan_Magistr_4
{
strings:
	$a0 = { 6467a1000083ec0489042464678926000033c0 }


condition:
	$a0
}