rule Win_Trojan_Gliss_2
{
strings:
	$a0 = { 041eb9df048bd683ea30b440cd21 }


condition:
	$a0
}