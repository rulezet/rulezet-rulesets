rule Win_Trojan_CB_2
{
strings:
	$a0 = { 81c4fa06fb3b26060073cd2e898c09065006561e33c0 }


condition:
	$a0
}