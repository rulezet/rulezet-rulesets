rule Win_Trojan_Date_3
{
strings:
	$a0 = { 010100550000000000ffff000000006f030000060000000903 }


condition:
	$a0
}