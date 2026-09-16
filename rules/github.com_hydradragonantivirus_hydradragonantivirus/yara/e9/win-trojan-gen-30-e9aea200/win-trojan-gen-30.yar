rule Win_Trojan_Gen_30
{
strings:
	$a0 = { 0606005e561e0e33ff8edfc50684002e }


condition:
	$a0
}