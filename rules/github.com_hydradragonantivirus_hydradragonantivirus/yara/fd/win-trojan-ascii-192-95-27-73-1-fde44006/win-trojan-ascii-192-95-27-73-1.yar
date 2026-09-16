rule Win_Trojan_Ascii_192_95_27_73_1
{
strings:
	$a0 = { 3139322e39352e32372e3733 }


condition:
	$a0
}