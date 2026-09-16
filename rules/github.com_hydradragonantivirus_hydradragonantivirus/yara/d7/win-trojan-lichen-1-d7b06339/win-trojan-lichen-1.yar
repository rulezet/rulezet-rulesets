rule Win_Trojan_Lichen_1
{
strings:
	$a0 = { 1e068becb43ebb3412cd218b76fa9c83c6f39d560f838700b449cd21b448bbffffcd2183eb41b448cd21bb4000b4 }


condition:
	$a0
}