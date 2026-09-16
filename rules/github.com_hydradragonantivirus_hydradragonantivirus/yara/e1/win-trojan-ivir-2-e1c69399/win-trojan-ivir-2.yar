rule Win_Trojan_Ivir_2
{
strings:
	$a0 = { bf00018b750103f75706a5a48ec183ee03bf0002b187f3a4fd91268785fffdabb83802f572f4fc07c3e90000b44233 }


condition:
	$a0
}