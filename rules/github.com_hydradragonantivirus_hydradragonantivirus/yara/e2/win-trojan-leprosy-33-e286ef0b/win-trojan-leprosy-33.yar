rule Win_Trojan_Leprosy_33
{
strings:
	$a0 = { 0f005bb99a02ba0001b440cd21e80100c3bb32018a27903226060188274381fbcc037ef0c3 }


condition:
	$a0
}