rule Win_Trojan_Gen_196
{
strings:
	$a0 = { 7604e8b60f598bf0eb0af74606040074038b760457b8150450b8d20350b8c80350b8c20350 }


condition:
	$a0
}