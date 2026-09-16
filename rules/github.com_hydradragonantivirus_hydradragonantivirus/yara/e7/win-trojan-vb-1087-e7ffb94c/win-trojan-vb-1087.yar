rule Win_Trojan_VB_1087
{
strings:
	$a0 = { 54726f76616f }

	$a1 = { 3600460037004500370046003700340037004300360033 }


condition:
	$a0 and $a1
}