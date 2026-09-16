rule Win_Trojan_Leonardo_1
{
strings:
	$a0 = { f5585b565352be7202bb2140ba00082e311c83c6024a75f75a5b5e }


condition:
	$a0
}