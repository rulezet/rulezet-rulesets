rule Win_Trojan_SillyE_5
{
strings:
	$a0 = { 06f0020e07a1d802a3dc02a1da02a3de02a1e202a3e40206b42fcd21891ee6028c06e802ba0c03b41acd21b824 }


condition:
	$a0
}