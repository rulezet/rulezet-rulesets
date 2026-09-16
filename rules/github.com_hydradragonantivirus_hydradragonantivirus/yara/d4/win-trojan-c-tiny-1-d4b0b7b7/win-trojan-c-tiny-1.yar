rule Win_Trojan_C_Tiny_1
{
strings:
	$a0 = { b9110133d2cd2132c0e863ffb440b91800ba1501cd21 }


condition:
	$a0
}