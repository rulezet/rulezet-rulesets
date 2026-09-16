rule Win_Trojan_Redol_1
{
strings:
	$a0 = { 8b44240c85c00f853a0000008b44240883f8040f }

	$a1 = { 726f6f6d006e006f0062006c00650072 }

	$a2 = { 7900000048414d4c4554 }


condition:
	$a0 and $a1 and $a2
}