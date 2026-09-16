rule Win_Trojan_VGEN_331
{
strings:
	$a0 = { 80e80100e88bf8e80100e88bd0e80100e8b02ae80100e8aa90e80100e8b02ee80100e890aae80100e8b043e80100e8 }


condition:
	$a0
}