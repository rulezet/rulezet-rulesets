rule Win_Trojan_Kitana_23
{
strings:
	$a0 = { 5683c616??b1918034??46e2fa5e9d7525 }


condition:
	$a0
}