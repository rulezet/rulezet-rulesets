rule Win_Trojan_Walrus_2
{
strings:
	$a0 = { 56a4a5b8dec0cd215e563dc0de74 }


condition:
	$a0
}