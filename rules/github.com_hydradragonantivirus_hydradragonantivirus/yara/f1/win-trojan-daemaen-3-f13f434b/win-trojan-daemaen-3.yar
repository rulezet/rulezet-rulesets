rule Win_Trojan_Daemaen_3
{
strings:
	$a0 = { 5e81eed107b99207b80000310446fec0fecce2f7c3 }


condition:
	$a0
}