rule Win_Trojan_Gen_153
{
strings:
	$a0 = { 803e8a0801740a833e900a127403e97efe803e8a08007514bf8c091e57bf10000e579a1806 }


condition:
	$a0
}