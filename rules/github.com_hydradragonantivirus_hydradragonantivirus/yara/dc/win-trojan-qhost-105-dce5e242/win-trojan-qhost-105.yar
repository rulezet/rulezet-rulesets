rule Win_Trojan_Qhost_105
{
strings:
	$a0 = { 73797374656d33325c647269766572735c6574635c686f737473 }

	$a1 = { 2e636f6d2e6272 }

	$a2 = { 6369746962616e6b }


condition:
	$a0 and $a1 and $a2
}