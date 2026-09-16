rule Win_Trojan_Mephisto_16
{
strings:
	$a0 = { 0b00b99903b4408d960001cd218b9603018db62e01b96a03d1 }


condition:
	$a0
}