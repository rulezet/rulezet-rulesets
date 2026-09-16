rule Win_Trojan_MtE2_1
{
strings:
	$a0 = { 5ab104d3ea83ea108cd903caba }


condition:
	$a0
}