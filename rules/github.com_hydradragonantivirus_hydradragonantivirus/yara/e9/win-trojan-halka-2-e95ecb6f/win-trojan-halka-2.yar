rule Win_Trojan_Halka_2
{
strings:
	$a0 = { 8d9e2d01c6070043e2fa5b53b440b9e8038d960b01cd215bb43ecd2168000158ffe0ffb803 }


condition:
	$a0
}