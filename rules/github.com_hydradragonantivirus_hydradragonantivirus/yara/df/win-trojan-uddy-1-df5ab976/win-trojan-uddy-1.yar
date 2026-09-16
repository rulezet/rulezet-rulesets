rule Win_Trojan_Uddy_1
{
strings:
	$a0 = { 02e83dfb5a83c23ce2ea32e4cd13b90300518e46fe33dbba8000b101b500b012b403cd1359e2ea }


condition:
	$a0
}