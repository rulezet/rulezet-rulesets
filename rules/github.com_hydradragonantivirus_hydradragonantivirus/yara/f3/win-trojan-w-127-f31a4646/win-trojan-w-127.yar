rule Win_Trojan_W_127
{
strings:
	$a0 = { eb2f5fb956010000e80800000000000000000000005e8b168bde83c30487fe9bdbe3db06db1b3113db03db1eade2f3eb0fe8ccffffff }


condition:
	$a0
}