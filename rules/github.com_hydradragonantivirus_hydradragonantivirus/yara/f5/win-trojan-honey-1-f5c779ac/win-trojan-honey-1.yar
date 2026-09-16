rule Win_Trojan_Honey_1
{
strings:
	$a0 = { 0e0e1f0789e58b760081ee0301e84e038b84560189845a01e98c01cd21cd13b44ccd21 }


condition:
	$a0
}