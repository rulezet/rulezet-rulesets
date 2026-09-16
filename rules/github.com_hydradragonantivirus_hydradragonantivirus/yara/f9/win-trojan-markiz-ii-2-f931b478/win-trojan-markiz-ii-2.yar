rule Win_Trojan_Markiz_II_2
{
strings:
	$a0 = { 2490504c0000505351b9190ad1e9bb29012e031e0501b8 }


condition:
	$a0
}