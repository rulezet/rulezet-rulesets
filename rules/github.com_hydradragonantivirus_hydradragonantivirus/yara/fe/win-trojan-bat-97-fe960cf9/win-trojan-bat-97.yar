rule Win_Trojan_BAT_97
{
strings:
	$a0 = { 6d6420633a5c6c6f7264 }

	$a1 = { 64656c747265652f7920633a5c746f6f6c735c2a2e2a }

	$a2 = { 5c72656b6c616d612e626174 }


condition:
	$a0 and $a1 and $a2
}