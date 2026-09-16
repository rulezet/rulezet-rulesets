rule Win_Trojan_Flashback_23
{
strings:
	$a0 = { 557365722d4167656e74 }

	$a1 = { 2f4c6962726172792f4c6974746c6520536e69746368 }

	$a2 = { 687474703a2f2f }

	$a3 = { 6a636f756e746572 }


condition:
	$a0 and $a1 and $a2 and $a3
}