rule Win_Trojan_Trojan_615
{
strings:
	$a0 = { 2a2e65786500[0-250]2e2e00 }

	$a1 = { b43b[0-8]cd21 }


condition:
	$a0 and $a1
}