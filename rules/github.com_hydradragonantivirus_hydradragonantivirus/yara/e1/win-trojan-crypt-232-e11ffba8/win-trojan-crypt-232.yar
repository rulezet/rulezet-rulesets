rule Win_Trojan_Crypt_232
{
strings:
	$a0 = { 13c0eb07f10da422eb2da013c4eb06070239a9 }

	$a1 = { 626b5164784b556a6961646e7c60 }


condition:
	$a0 and $a1
}