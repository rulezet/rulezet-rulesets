rule Win_Trojan_2UP_1
{
strings:
	$a0 = { 5100eb629033c08ec0bd6c04268a56002ec60613050090 }


condition:
	$a0
}