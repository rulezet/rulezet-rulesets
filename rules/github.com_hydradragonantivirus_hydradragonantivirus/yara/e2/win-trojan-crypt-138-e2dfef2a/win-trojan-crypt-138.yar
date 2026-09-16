rule Win_Trojan_Crypt_138
{
strings:
	$a0 = { ba????????b900000009[0-30]0f31[0-6]0fa2[0-30]58????ffe0 }


condition:
	$a0
}