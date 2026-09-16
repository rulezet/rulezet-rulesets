rule Win_Trojan_Loz_9
{
strings:
	$a0 = { 5e83ee06bf0001f3a4b8eeffcd213dffee7503e98c00b44abb0020cd21b448bbffffcd2183eb45b448cd2150bb }


condition:
	$a0
}