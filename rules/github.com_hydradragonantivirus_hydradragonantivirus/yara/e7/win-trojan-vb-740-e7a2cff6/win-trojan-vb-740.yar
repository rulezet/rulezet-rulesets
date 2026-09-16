rule Win_Trojan_VB_740
{
strings:
	$a0 = { 746c6f7a65406d61696c2e7275[0-15]6d6f6465786e }

	$a1 = { 4c004f0047[0-11]5200450050004f00520054 }


condition:
	$a0 and $a1
}