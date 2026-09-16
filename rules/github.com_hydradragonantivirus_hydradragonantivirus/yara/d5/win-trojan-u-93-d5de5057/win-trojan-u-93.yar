rule Win_Trojan_U_93
{
strings:
	$a0 = { dfe02308780670bc2183d089e54c223be386e32ea9064f0c29c15632970a917dc7692f0bc56993bec54ba9cac54a8fee }


condition:
	$a0
}