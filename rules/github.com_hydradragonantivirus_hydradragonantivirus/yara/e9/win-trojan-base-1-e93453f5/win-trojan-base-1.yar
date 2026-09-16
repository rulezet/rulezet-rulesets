rule Win_Trojan_Base_1
{
strings:
	$a0 = { cd218bd581c25402b90700b43fcd21fc }


condition:
	$a0
}