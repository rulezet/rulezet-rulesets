rule Win_Trojan_Flooder_24
{
strings:
	$a0 = { e86f2b000050e8733601 }

	$a1 = { 7233325c726f6f742e626174[0-87]7233325c6d6972632e42414b }

	$a2 = { 5c726f6f742e726567 }


condition:
	$a0 and $a1 and $a2
}