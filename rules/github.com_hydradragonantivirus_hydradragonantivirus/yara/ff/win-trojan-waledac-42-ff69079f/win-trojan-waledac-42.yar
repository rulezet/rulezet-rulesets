rule Win_Trojan_Waledac_42
{
strings:
	$a0 = { c1e2026603cfb883855fe1e916fdffffcbede5264c80c11ad3f9c0e3010bd8 }


condition:
	$a0
}