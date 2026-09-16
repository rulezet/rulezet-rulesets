rule Win_Trojan_Leprosy_26
{
strings:
	$a0 = { 028bd8b91400ba0b02b43fcd21bb0b028a260301886706be0001bf0b028cd88ec0fcf3a67513 }


condition:
	$a0
}