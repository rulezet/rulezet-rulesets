rule anti_debug__IsDebuggerPresent__8_byt_STR_17_
{
strings:
	$a0 = { 4973446562756767657250726573656e74 }

condition:
	$a0
}