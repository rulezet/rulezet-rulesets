rule Win_Trojan_Grog_25
{
strings:
	$a0 = { 0583fc7522817c07fa74751b817c0a83fc7514817c0c }


condition:
	$a0
}