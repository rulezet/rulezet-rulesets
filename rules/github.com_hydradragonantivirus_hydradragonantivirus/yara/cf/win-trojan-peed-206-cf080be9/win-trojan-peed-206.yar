rule Win_Trojan_Peed_206
{
strings:
	$a0 = { 45fff6bf6e229600905ec1eb578d35163724008bddfff185c35f }


condition:
	$a0
}