rule Win_Trojan_DEI_2
{
strings:
	$a0 = { 77373d1c00723226894515e82c01bafb06b91c00b440cd2126c745150000ba9a06b440cd21 }


condition:
	$a0
}