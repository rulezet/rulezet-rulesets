rule Win_Trojan_B_32
{
strings:
	$a0 = { 80fc0074052eff2e2c025053515256571e062e88162b02b8 }


condition:
	$a0
}