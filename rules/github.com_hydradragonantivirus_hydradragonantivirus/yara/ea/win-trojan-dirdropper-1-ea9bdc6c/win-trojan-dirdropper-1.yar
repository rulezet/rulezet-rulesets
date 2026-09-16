rule Win_Trojan_DirDropper_1
{
strings:
	$a0 = { cd218c060a010e07b4b6b91604be0e018bfeac32c4aae2fa }


condition:
	$a0
}