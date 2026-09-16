rule Win_Trojan_Iblis_1
{
strings:
	$a0 = { b9fc00ba360103d5cd21b80042b90000ba0000cd213e }


condition:
	$a0
}