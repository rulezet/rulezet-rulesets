rule Win_Trojan_Vecna_1
{
strings:
	$a0 = { b97e00813500004747e2f8c3 }


condition:
	$a0
}