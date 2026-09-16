rule Win_Trojan_Riot_13
{
strings:
	$a0 = { 0500e80f00b440b935018d960001cd21e80100c38b9e0e018db63401b98100311c4646e2fa }


condition:
	$a0
}