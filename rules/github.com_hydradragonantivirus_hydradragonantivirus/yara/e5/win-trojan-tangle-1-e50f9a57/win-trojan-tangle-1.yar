rule Win_Trojan_Tangle_1
{
strings:
	$a0 = { 324975fd4975fd4975fd4975fd4975fdeb01eafa56578b3e0101eb01ea81c734018bf7b94901b4 }


condition:
	$a0
}