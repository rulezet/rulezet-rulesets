rule Win_Trojan_Funtime_2
{
strings:
	$a0 = { 2553797374656d526f6f74255c53797374656d33325c66756e74696d65 }


condition:
	$a0
}