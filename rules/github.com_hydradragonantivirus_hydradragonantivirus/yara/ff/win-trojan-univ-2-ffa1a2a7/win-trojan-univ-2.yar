rule Win_Trojan_Univ_2
{
strings:
	$a0 = { 3ec686a602e93e8b8690022d0200483e8986a702b800429033c933d2cd21b440b9030033c9 }


condition:
	$a0
}