rule Win_Trojan_B_101
{
strings:
	$a0 = { 01bd0103e81100c333c0cd16bf1880b9a60133c0f2aaebe1ba8000b404508bc5cd1358720bfec1 }


condition:
	$a0
}