rule Win_Trojan_Agent_35443
{
strings:
	$a0 = { 33d0e932feffff8bdb83c404ffd0e8b70300008b }

	$a1 = { 0e58415c36716b7e9faa29 }


condition:
	$a0 and $a1
}