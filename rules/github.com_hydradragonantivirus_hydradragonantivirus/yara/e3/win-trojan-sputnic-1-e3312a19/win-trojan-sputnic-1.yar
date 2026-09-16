rule Win_Trojan_Sputnic_1
{
strings:
	$a0 = { 50e84b0859598946fab8b80150b8b20150e83b0859598946fcb864005033c050e8281f5959 }


condition:
	$a0
}