rule anti_debug__Softice_____SIWVID__8_byt_STR_11_
{
strings:
	$a0 = { 5c5c2e5c53495756494400 }

condition:
	$a0
}