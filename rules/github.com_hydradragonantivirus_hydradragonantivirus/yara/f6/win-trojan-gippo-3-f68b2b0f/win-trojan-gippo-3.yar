rule Win_Trojan_Gippo_3
{
strings:
	$a0 = { 5351521e060e1fbe2f00b9f7018b04ba59220bc2f7d021 }


condition:
	$a0
}