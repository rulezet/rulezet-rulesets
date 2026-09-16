rule Win_Trojan_Clicker_55
{
strings:
	$a0 = { 6a096a006a00688c20450068c82045008bc3e8c29afeff50e86834fdffe8cb24fbff5bc3 }


condition:
	$a0
}