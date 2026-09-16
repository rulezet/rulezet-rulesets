rule Win_Trojan_Peed_433
{
strings:
	$a0 = { 5589e581ec4c00000090b80200000050 }


condition:
	$a0
}