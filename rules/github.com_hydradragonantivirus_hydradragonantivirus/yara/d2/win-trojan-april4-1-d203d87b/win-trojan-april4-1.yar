rule Win_Trojan_April4_1
{
strings:
	$a0 = { e91fffb81005ba8000b91000cd13cf32c0cfb4408d9600012e8b8eed032e8b9e1b01cd213bc1 }


condition:
	$a0
}