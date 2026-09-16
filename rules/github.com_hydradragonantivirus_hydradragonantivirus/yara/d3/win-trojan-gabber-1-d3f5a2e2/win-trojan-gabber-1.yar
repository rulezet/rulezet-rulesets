rule Win_Trojan_Gabber_1
{
strings:
	$a0 = { b801faba4559cd16e800009090905e81ee11018bee81fc4a4a74118db68d03bf000081c7000157a4a5a5eb121e060e }


condition:
	$a0
}