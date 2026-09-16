rule Win_Trojan_Bancos_1728
{
strings:
	$a0 = { 4029b4ce70af98b6809139862dcdfab61d62a541e059b792f54dc97f994dda5f63a4554e44dfad23ad0cf1fe1268bfaa0639f4c1ae3a9e3175635b2ea3857b73c4b53f15b605 }


condition:
	$a0
}