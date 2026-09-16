rule Win_Trojan_G2_6
{
strings:
	$a0 = { 1000b9fd002e812f332b83c302e2f61b2c3388b418462b3949eb6c77f85468867ba76ebf037bb90bad612e33ab33ac }


condition:
	$a0
}