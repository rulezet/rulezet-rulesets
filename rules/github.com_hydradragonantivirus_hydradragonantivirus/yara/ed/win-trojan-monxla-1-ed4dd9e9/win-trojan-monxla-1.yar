rule Win_Trojan_Monxla_1
{
strings:
	$a0 = { 5b8ec0bf00005e5683c61aacb900 }


condition:
	$a0
}