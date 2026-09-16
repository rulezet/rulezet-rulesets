rule Win_Trojan_Mini_8
{
strings:
	$a0 = { cd2193b43fb25ffec65459cd21a31701055f0050b800429933c9cd2159b440fec6cd21b43ecd }


condition:
	$a0
}