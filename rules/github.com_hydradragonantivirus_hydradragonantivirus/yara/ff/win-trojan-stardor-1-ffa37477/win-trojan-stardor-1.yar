rule Win_Trojan_Stardor_1
{
strings:
	$a0 = { f6b9080033db51b90100d1c250cd26 }


condition:
	$a0
}