rule Win_Trojan_Fire_3
{
strings:
	$a0 = { f6e80f00eb0400000000e80600eb1b00000000e80000589681ee17018dbc2b01b9d60280350147e2fac3 }


condition:
	$a0
}