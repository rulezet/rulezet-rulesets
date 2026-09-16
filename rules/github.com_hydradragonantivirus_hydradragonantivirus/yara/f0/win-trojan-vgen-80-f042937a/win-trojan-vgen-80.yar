rule Win_Trojan_VGEN_80
{
strings:
	$a0 = { 5ab801faba4559cd16ba6001b44ecd21e85200ba5a01b44ecd21e84800b409ba2701cd21cd20546869732070726f67 }


condition:
	$a0
}