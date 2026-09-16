rule Win_Trojan_Haxdoor_127
{
strings:
	$a0 = { 68687f03fe747470733a2f2f38652d676f6c642e582f7f67bf4d362f00797769 }


condition:
	$a0
}