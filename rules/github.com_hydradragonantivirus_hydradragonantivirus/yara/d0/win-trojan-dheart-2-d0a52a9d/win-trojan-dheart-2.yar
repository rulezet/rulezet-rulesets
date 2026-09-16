rule Win_Trojan_DHeart_2
{
strings:
	$a0 = { 03b80042cd217214baeb028106ed020001b906008b1e4803b440cd218b1e4803b43ecd2180 }


condition:
	$a0
}