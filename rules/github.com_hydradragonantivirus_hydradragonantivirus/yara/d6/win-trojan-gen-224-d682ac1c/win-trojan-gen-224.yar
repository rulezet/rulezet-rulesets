rule Win_Trojan_Gen_224
{
strings:
	$a0 = { 02d850e4d5408c9d0c1ab75bbaef029695ef01d730d2bb1b4128d1d7ba0103af4396954d06d7fd9d }


condition:
	$a0
}