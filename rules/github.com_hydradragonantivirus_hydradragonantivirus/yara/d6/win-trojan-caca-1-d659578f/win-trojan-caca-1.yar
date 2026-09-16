rule Win_Trojan_CACA_1
{
strings:
	$a0 = { 067901414a830671012990b800429933c9cd21b440b92000ba6701cd21b402b207cd21b43ecd21 }


condition:
	$a0
}