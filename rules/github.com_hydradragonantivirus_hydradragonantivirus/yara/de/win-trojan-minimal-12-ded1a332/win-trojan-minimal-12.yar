rule Win_Trojan_Minimal_12
{
strings:
	$a0 = { 010100558e00000000ffff3203000084000000050000003203 }


condition:
	$a0
}