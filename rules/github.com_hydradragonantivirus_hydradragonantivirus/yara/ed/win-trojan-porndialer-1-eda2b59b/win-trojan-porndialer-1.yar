rule Win_Trojan_PornDialer_1
{
strings:
	$a0 = { 294669721d1f1cf888874eb974c667692a8520ec0ecc69333d8e3c4ffb8f025c44d7502e4558451f }


condition:
	$a0
}