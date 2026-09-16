rule Win_Trojan_CPP_3
{
strings:
	$a0 = { 25ba5202cd21610e1f0e07c3b003cfb440cd212bc92bd264894c15b602b1048bfaebe43d004b74 }


condition:
	$a0
}