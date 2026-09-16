rule Win_Trojan_Spanz_1
{
strings:
	$a0 = { 3d750683c7051feb0fb9ff7f33c0f2ae803d0075db }


condition:
	$a0
}