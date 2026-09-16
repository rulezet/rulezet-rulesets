rule Win_Trojan_Neuroquila_7
{
strings:
	$a0 = { 0e1f8d36????f8811c????81eefeffb8????f7d803c6f57303e9eaff }


condition:
	$a0
}