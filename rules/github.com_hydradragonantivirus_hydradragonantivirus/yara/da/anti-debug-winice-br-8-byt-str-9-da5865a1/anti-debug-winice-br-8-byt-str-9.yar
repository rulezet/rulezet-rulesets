rule anti_debug__WINICE_BR__8_byt_STR_9_
{
strings:
	$a0 = { 57494e4943452e4252 }

condition:
	$a0
}