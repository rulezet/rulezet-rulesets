rule Win_Spyware_ye_48
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]2df3378c486f1a4c761b46b0d0f5ad }


condition:
	$a0
}