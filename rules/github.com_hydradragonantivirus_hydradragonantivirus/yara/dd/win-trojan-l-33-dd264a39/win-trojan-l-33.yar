rule Win_Trojan_L_33
{
strings:
	$a0 = { 028a27322606012a26060188274381fb70057eedc3 }


condition:
	$a0
}