rule Win_Trojan_Virus101_1
{
strings:
	$a0 = { 03b49003f3b4ea8cc8b7448cdbb5ea39c3b4f07411b4e9be0010 }


condition:
	$a0
}