rule Win_Trojan_Suriv_2
{
strings:
	$a0 = { 03f72e8b8d1500cd218cc80510008ed0 }


condition:
	$a0
}