rule Win_Trojan_Grozny_3
{
strings:
	$a0 = { fbb42fbe110703f552518bd581c200010652cd21b41a5a06cd2187dfb440b96906cd2187df9f07 }


condition:
	$a0
}