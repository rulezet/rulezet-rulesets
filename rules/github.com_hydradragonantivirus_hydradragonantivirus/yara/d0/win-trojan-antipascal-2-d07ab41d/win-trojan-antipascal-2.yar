rule Win_Trojan_AntiPascal_2
{
strings:
	$a0 = { cd2132c0e82700582d0300a38000b90300ba7f00b440cd21b002e81100b98d0233d2b440cd21 }


condition:
	$a0
}