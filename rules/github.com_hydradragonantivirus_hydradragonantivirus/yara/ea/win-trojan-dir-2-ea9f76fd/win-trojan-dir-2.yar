rule Win_Trojan_Dir_2
{
strings:
	$a0 = { 260e1f580e1fbe000156c30e0e1f07 }


condition:
	$a0
}