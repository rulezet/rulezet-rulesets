rule Win_Trojan_Boot_6
{
strings:
	$a0 = { c0508ed8be257cb103d20c4681fec87d72f7eb008b }


condition:
	$a0
}