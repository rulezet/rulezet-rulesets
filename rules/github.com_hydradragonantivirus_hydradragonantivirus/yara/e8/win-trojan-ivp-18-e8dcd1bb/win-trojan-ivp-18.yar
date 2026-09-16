rule Win_Trojan_IVP_18
{
strings:
	$a0 = { 01b913032e8a272e32a43f042e882743e2f2c3 }


condition:
	$a0
}