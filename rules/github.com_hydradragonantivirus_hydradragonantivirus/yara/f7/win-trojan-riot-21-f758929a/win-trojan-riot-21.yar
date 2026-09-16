rule Win_Trojan_Riot_21
{
strings:
	$a0 = { b915018d964801cd21b80042b90000ba0000cd21b440b905008d961502cd21fe860902b43ecd }


condition:
	$a0
}