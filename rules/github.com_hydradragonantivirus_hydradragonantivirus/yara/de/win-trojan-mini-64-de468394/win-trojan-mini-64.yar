rule Win_Trojan_Mini_64
{
strings:
	$a0 = { ba9e00cd2193b43fba5001905459cd21055000905033c9f7e1b442cd2159b4405a52cd21b4 }


condition:
	$a0
}