rule Win_Trojan_Banker_6381
{
strings:
	$a0 = { 85c07407b2018b08ff51fcc3 }

	$a1 = { 656d61696c3d[2-50]66726f6d3d[2-50]6d6573736167653d[2-50]687474703a2f2f[2-50]2e706870 }


condition:
	$a0 and $a1
}