rule Win_Trojan__0175_0006_000_1
{
strings:
	$a0 = { 01b99c00565781c69a00e830005a5eb440cd21b43ecd21ebd1b99c0003e1b4098d944e00cd21c3 }


condition:
	$a0
}