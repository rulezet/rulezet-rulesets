rule Win_Trojan_Small_185
{
strings:
	$a0 = { 8ec3bf8002fab140f3a4a674114e4fa456be8400566626a55fb028abab5e5f2bce0e07f3a4c380fc407513608bf2803ce9750a1e0e1fb9410099cd211f61 }


condition:
	$a0
}