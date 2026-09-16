rule Win_Trojan_Small_4335
{
strings:
	$a0 = { e8??000000(e9|e8)??0000008d2d2ec94705 }


condition:
	$a0
}