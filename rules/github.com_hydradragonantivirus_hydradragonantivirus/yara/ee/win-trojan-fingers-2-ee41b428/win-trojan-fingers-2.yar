rule Win_Trojan_Fingers_2
{
strings:
	$a0 = { 9404733e585af9c3b405b500b100b6 }


condition:
	$a0
}