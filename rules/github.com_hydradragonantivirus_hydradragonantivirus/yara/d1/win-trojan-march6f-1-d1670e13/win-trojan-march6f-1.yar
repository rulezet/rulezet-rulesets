rule Win_Trojan_MARCH6F_1
{
strings:
	$a0 = { 02b90700890e9301b80103ba8000cd1372aabe9b03bf9b01b96900f3a4b8010333dbfec1cd13 }


condition:
	$a0
}