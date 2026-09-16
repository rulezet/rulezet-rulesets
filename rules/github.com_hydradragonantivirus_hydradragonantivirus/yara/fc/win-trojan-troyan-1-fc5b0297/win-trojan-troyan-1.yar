rule Win_Trojan_Troyan_1
{
strings:
	$a0 = { 2e8c069a00b80835cd212e891e96002e }


condition:
	$a0
}