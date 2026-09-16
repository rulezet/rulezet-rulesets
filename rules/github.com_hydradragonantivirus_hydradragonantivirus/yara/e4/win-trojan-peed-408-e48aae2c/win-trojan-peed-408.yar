rule Win_Trojan_Peed_408
{
strings:
	$a0 = { 928d9417b133000081ea0fb0ffff81faf14f0000 }


condition:
	$a0
}