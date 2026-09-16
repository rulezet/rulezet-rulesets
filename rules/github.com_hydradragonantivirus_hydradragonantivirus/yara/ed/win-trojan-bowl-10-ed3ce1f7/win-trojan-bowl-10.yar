rule Win_Trojan_Bowl_10
{
strings:
	$a0 = { 87038d960301cd212efe067204eb890ee84900b43b }


condition:
	$a0
}