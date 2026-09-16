rule Win_Trojan_GR_2
{
strings:
	$a0 = { b96303d3d2cc0bd3bee570bf9bb2bbf153b2e0b461cd2136299c }


condition:
	$a0
}