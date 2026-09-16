rule Win_Trojan_Rainbow_3
{
strings:
	$a0 = { 5e83ee03b8ad1bcd133dedde754a90900e1f81c69807813c4d5a740c }


condition:
	$a0
}