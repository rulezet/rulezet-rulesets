rule Win_Trojan_Haj_1
{
strings:
	$a0 = { 2a2e6261742920646f2063616c6c202530202f68616a5f7020252561 }


condition:
	$a0
}