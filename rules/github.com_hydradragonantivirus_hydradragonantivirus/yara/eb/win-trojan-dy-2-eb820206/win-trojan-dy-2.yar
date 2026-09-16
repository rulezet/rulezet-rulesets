rule Win_Trojan_Dy_2
{
strings:
	$a0 = { 2ea3fe00b440b90801ba0000cd210e1fb440b91500baf301cd21b800425a59cd21ff363901 }


condition:
	$a0
}