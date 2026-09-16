rule Win_Trojan_Gippo_4
{
strings:
	$a0 = { 5351521e060e1fbe2f00b9f7018b04ba0b3b0bc2f7d021 }


condition:
	$a0
}