rule Win_Trojan_Troi_6
{
strings:
	$a0 = { 2d2d3efc0e1f2bf68ec6bf0002b99801f3a4061fa18400a3 }


condition:
	$a0
}