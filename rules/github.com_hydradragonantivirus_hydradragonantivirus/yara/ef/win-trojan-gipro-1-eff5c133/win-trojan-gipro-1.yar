rule Win_Trojan_Gipro_1
{
strings:
	$a0 = { 8c0602030e07a1d802a3dc02a1da02a3de02a1e202a3e40206b42fcd21891ef8028c06fa02ba1e03b41acd21b824 }


condition:
	$a0
}