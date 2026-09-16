rule Win_Trojan_Crypted_16
{
strings:
	$a0 = { 558bec83ec28535657 }

	$a1 = { 8b45fc8b40148945d88b45fc8b40108945dc }

	$a2 = { 488945f8eb078b45f8488945 }


condition:
	$a0 and $a1 and $a2
}