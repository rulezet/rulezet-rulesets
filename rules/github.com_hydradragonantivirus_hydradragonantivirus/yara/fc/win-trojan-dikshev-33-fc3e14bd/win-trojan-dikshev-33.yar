rule Win_Trojan_Dikshev_33
{
strings:
	$a0 = { 9e00bf3c0157acaa3c0074093c2e75f6be3801ebf15ab45bcd21720893b440ba3c0087d1ebd4 }


condition:
	$a0
}