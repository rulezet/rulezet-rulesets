rule Win_Trojan_SdBot_3643
{
strings:
	$a0 = { 1cc893d57aecac39a34a9e4d1aea63379c1894c8eaa1d2db1cb20da05ca0ee786eb050f1df23fd1eb1ea07175fbbbf91148096ba144c1ad67b3ece7451bd0c88a6b39dbcc3f5c705f0b098e80383 }


condition:
	$a0
}