rule Win_Trojan_AAA_1
{
strings:
	$a0 = { c2428ae42bc98ae4cd218ae473058ae4e97e02bb9a008ae4b829048ae403078ae4488ae4408ae4 }


condition:
	$a0
}