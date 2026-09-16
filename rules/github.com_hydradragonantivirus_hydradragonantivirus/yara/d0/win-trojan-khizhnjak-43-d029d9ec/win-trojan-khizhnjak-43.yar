rule Win_Trojan_Khizhnjak_43
{
strings:
	$a0 = { b92300b44ecd21730debc6e8????b44fcd217302ebbb }


condition:
	$a0
}