rule Win_Trojan_N_11
{
strings:
	$a0 = { 061f33ede87400b440b9c802ba0000cd21b800429933c9cd21b440b90300babe02cd21b801 }


condition:
	$a0
}