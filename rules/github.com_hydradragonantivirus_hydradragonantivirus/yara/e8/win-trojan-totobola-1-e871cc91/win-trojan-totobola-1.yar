rule Win_Trojan_Totobola_1
{
strings:
	$a0 = { 2d03002e8986b401b440b933018d960001cd2132c0e89900b440b904008d96b301cd21b43e }


condition:
	$a0
}