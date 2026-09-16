rule Win_Trojan_Chemist_1
{
strings:
	$a0 = { 3b00be10018a2480f4aa882446e2f6 }


condition:
	$a0
}