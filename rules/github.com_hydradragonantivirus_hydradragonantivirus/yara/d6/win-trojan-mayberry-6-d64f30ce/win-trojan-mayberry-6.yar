rule Win_Trojan_Mayberry_6
{
strings:
	$a0 = { fd02b440b9f601908d960601cd21b800429933c9cd21b440b91c008d96f902cd21 }


condition:
	$a0
}