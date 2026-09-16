rule Win_Trojan_Draw_2
{
strings:
	$a0 = { b002e640b003e640bada03ecb2c0b033ee2ea12600ee02c4a8087404f6d402c42ea326005aff00b8 }


condition:
	$a0
}