rule Win_Trojan_Bancos_827
{
strings:
	$a0 = { 7eeba3a7ba6211427eb45d6efe96ed8fea674dfe6e974efda5fd3e5743d53cd3b6b7bb74f6ab7be7dafcc95adb425bdcfa01276d8786e1734f7a3aab37b1213fc29591b11ae7f45ab72d3f }


condition:
	$a0
}