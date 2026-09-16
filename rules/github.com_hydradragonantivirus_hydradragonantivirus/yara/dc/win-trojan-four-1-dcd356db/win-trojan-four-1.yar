rule Win_Trojan_Four_1
{
strings:
	$a0 = { 010100550000000000ffff6a08000010190000020000006a08 }


condition:
	$a0
}