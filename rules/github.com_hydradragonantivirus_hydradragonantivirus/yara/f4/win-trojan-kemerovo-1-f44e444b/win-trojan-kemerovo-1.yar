rule Win_Trojan_Kemerovo_1
{
strings:
	$a0 = { 89c7b90400a4e2fd89d729d381eb }


condition:
	$a0
}