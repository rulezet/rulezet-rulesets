rule Win_Trojan_Dridex_24
{
strings:
	$a0 = { 5589e583ec0c[0-32]6a006a00e8????ffff[0-32]6a016a00e8????ffff[0-16]6a006a01e8????ff }


condition:
	$a0
}