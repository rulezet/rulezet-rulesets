rule Win_Trojan_Kela_8
{
strings:
	$a0 = { 8bfe2e8ba413036a00078bd683c70c2e8ba413032e }


condition:
	$a0
}