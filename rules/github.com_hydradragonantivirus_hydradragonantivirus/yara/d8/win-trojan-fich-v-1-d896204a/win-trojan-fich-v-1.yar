rule Win_Trojan_Fich_V_1
{
strings:
	$a0 = { 35cd218c062901891e2b01b80335cd218c062d01891e }


condition:
	$a0
}