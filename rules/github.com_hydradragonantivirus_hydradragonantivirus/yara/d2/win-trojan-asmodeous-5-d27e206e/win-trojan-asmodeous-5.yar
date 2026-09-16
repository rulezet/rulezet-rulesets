rule Win_Trojan_Asmodeous_5
{
strings:
	$a0 = { 5b83c3358bf381ee7f0cfdfc0e1fb9c00051b90800fdfc8a17d0d2e80c0046e2f85943e2ec }


condition:
	$a0
}