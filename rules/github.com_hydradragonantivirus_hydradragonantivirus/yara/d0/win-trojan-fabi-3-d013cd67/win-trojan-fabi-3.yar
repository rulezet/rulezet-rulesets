rule Win_Trojan_Fabi_3
{
strings:
	$a0 = { e8000000005d81ed061040008db52a104000b95e250000bbb1a23b76311ead81c39663dc48e2f5 }


condition:
	$a0
}