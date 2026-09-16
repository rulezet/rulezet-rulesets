rule Win_Spyware_ye_77
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]4a9054a1650cbfe98b3053456d0aba }


condition:
	$a0
}