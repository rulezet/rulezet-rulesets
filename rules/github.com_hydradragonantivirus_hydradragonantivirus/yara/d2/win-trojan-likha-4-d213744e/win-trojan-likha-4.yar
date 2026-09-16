rule Win_Trojan_Likha_4
{
strings:
	$a0 = { 8cc88ed8e84dfd750bb409baac0ccd21b44ccd21fc060e07be8e04b94800e897f4 }


condition:
	$a0
}