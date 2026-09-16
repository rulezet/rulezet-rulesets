rule Win_Trojan_Squatter_2
{
strings:
	$a0 = { 8bec5e3976000f859b001e06b430cd213c05cd030f825a0133ffb452cd2126c55f128b471f3dffff74258ed8803d5a7408 }


condition:
	$a0
}