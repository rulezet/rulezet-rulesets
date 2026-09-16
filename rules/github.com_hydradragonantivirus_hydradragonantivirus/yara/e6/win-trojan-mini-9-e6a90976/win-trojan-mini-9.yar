rule Win_Trojan_Mini_9
{
strings:
	$a0 = { 9e0052cd2193061fb43f575a5459cd2150b800429933c9cd2159890e1d0183c161b440565acd21 }


condition:
	$a0
}