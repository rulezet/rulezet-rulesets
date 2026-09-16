rule Win_Trojan_Jackal_1
{
strings:
	$a0 = { c606a40600c606ab022ffce8810a0e07e8a70ab452cd21268b47fe }


condition:
	$a0
}