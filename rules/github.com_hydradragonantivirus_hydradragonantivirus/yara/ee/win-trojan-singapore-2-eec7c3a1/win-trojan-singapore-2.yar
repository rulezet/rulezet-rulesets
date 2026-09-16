rule Win_Trojan_Singapore_2
{
strings:
	$a0 = { 088bd6fcb90300bf0001f3a49f80fcb7751e2ea3e8042e891eed042e890ef1042e8916f4042e893ef604e8eaff }


condition:
	$a0
}