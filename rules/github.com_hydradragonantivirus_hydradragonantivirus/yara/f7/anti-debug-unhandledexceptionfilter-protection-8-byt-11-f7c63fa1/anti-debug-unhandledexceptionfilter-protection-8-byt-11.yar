rule anti_debug__UnhandledExceptionFilter_protection__8_byt_11_
{
strings:
	$a0 = { b906000000b0ccf2ae85c9 }

condition:
	$a0
}