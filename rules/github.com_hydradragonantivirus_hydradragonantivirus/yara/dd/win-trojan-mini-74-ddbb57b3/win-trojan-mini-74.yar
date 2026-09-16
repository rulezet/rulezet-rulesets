rule Win_Trojan_Mini_74
{
strings:
	$a0 = { 3fba59015459cd215087f2ac3c925874130559005033c9f7e1b442cd2159b4405a52cd21b44feb }


condition:
	$a0
}