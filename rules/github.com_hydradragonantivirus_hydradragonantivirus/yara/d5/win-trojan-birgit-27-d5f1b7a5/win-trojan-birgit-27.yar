rule Win_Trojan_Birgit_27
{
strings:
	$a0 = { c6869a02e92e899e9b02b90300eb005133c9e85600b002e84700b4408d969a0259cd217210 }


condition:
	$a0
}