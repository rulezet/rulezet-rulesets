rule Win_Trojan_Marbas_1
{
strings:
	$a0 = { 17018bfeb9c404ac3400aae2fae5400d2da125ffbf88861806c3 }


condition:
	$a0
}