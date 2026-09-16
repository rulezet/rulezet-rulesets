rule Win_Trojan_Plastique2900_1
{
strings:
	$a0 = { 4bbf0001be540b03f72e8b8d3500 }


condition:
	$a0
}