rule Win_Trojan_IVP_10
{
strings:
	$a0 = { c686cc02e92e899ecd02b90300eb005133c9e85600b002e84700b4408d96cc0259cd217210 }


condition:
	$a0
}