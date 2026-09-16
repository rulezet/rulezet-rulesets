rule Win_Trojan_R_48
{
strings:
	$a0 = { 1700eb2790e811008d960301b99c01b440cd21e80300c3 }


condition:
	$a0
}