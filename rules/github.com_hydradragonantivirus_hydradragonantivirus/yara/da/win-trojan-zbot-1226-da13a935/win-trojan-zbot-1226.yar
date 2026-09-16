rule Win_Trojan_Zbot_1226
{
strings:
	$a0 = { 33c0ba8717ef1d33c9bbf20241003d0f2700007502281343c1ea084183f904750aba }


condition:
	$a0
}