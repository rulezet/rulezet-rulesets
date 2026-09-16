rule Win_Trojan_Hamster_1
{
strings:
	$a0 = { 5d81ed07012ec786a802e902b90300be0d0303f5bf0001f3a4b90c00beea0203f5bff70203fde83e01b41aba26 }


condition:
	$a0
}