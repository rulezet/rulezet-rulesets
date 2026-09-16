rule Win_Trojan_Trojan_608
{
strings:
	$a0 = { 2e2e00[0-250]2a2e434f4d00 }

	$a1 = { b43b[0-8]cd21 }


condition:
	$a0 and $a1
}