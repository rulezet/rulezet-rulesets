rule Win_Trojan_Arriba_1
{
strings:
	$a0 = { 031e0633c0501fbe84008b44028ec08b3c26817d }


condition:
	$a0
}