rule Win_Trojan_Mini_59
{
strings:
	$a0 = { cd2193b43f5459ba420190cd21803e4201917414054200905033c9f7e1b442cd218bd659b440 }


condition:
	$a0
}