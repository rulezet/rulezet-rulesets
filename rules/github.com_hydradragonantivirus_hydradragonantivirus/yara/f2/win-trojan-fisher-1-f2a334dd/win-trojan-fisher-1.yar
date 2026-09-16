rule Win_Trojan_Fisher_1
{
strings:
	$a0 = { 741780fc4e741580fc4f741080fc3d742e3d03cc7409e9 }


condition:
	$a0
}