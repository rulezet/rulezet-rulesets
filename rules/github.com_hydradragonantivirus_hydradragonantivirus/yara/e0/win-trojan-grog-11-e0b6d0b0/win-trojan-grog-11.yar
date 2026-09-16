rule Win_Trojan_Grog_11
{
strings:
	$a0 = { d28eda8ec2be04008bfead50ad50b82701ab8cc8ab0e1fb9c90abe4001fec6529dace2fdcd20 }


condition:
	$a0
}