rule Win_Trojan_MarkII_1
{
strings:
	$a0 = { fc8856008a57fd8856018a57fe88560253eb07902a2e }


condition:
	$a0
}