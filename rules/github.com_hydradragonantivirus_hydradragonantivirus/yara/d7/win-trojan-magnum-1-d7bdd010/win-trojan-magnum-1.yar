rule Win_Trojan_Magnum_1
{
strings:
	$a0 = { 8e03000000ffff4903000098720000040000004903 }


condition:
	$a0
}