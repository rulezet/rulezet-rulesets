rule Win_Trojan_Vgen_112
{
strings:
	$a0 = { f7f7dd55c3b8c130cd2181fb0100743c8cc8488ec0a102002d940026812e03009400a302002d10008ec0b99104bf }


condition:
	$a0
}