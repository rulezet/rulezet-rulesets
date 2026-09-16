rule Win_Trojan_VBkrypt_2
{
strings:
	$a0 = { 52004f00590041004e004f005c0043005200590050005400 }


condition:
	$a0
}