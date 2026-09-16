rule Win_Trojan_Uri_1
{
strings:
	$a0 = { 67009a73003b005589e581ec000331c0a37218bffd001e578dbe00ff165731c0509acf0867009a9d066700bffd }


condition:
	$a0
}