rule Win_Trojan_Dikshev_25
{
strings:
	$a0 = { 2ab99e00b44e87ce8bd1cd217301c38bd6ac3c2e75fbc704636fc644026db45bcd2172ea93b440b23087d1eb }


condition:
	$a0
}