rule Win_Trojan_Gawenda_1
{
strings:
	$a0 = { a3018d940901cd21b43ecd21b801438b8c6f028d94 }


condition:
	$a0
}