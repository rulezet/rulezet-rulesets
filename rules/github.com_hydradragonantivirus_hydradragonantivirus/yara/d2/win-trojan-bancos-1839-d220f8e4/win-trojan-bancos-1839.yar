rule Win_Trojan_Bancos_1839
{
strings:
	$a0 = { 0dcc7aea811e488db69a3efaaf4a7819203f865aa821fe526b6b475f3b01d574b2e76d30068555f640e489ac9ac5839f440b24ac2c60a363b8babfe6119fc89f977c5e11ce3a }


condition:
	$a0
}