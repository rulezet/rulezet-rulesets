rule Win_Trojan_Fakealert_122
{
strings:
	$a0 = { 526567436c65616e }

	$a1 = { 5c44697361626c656442484f5c }

	$a2 = { 5c4c6f67 }


condition:
	$a0 and $a1 and $a2
}