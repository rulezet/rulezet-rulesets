rule Win_Trojan_Peace_2
{
strings:
	$a0 = { 4b741090909080fcff74239090902eff2e35002e8c1e }


condition:
	$a0
}