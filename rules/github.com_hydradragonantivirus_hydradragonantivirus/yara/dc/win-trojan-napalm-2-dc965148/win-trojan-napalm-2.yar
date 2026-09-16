rule Win_Trojan_Napalm_2
{
strings:
	$a0 = { 44008b038b15b4954400e8715effff8b03e8ea5effff5be80076fbffffffffff0c000000424f2d424f20436c69656e74 }


condition:
	$a0
}