rule Win_Trojan_Dead_6
{
strings:
	$a0 = { 4233c999e82e00b440b90500ba3101e82300b8024233c999e81a00b440b9470133d2e8 }


condition:
	$a0
}