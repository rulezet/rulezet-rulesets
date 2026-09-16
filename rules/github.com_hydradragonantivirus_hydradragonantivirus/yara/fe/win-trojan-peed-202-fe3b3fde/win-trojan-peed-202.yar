rule Win_Trojan_Peed_202
{
strings:
	$a0 = { e85c00000068f83200006800??40005a59526a00ff32e82900000005 }


condition:
	$a0
}