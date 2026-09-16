rule Win_Trojan_Bancos_1766
{
strings:
	$a0 = { f42093e8ea3cfc4b4a9f047558b2e9e0cf123ce0e9c9386121ac9ec35ee9bf0ec9b806fe0e4c85748603c6a4e9e674ecfb15071747e42001a9e66521e92f35311f8f1caf99a7 }


condition:
	$a0
}