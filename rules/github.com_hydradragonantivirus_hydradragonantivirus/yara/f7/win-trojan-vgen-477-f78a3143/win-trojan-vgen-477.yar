rule Win_Trojan_VGEN_477
{
strings:
	$a0 = { babacd213dcaca744fb82135cd212e891e63012e8c0665018cd8488ec026a103002d1a0093b44a1e07cd21b448bb19 }


condition:
	$a0
}