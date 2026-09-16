rule Win_Trojan_VGEN_718
{
strings:
	$a0 = { 901a90cd2090e800005d81ed0b01e80400eb2f00008b9615018db64401b98d01311483c602e2f9c3b42ccd218996 }


condition:
	$a0
}