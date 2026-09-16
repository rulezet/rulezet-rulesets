rule anti_debug__Rose_s_UAC__8_byt_24_
{
strings:
	$a0 = { 1e6631c08ed866f71505000000eb019a66f715050000001f }

condition:
	$a0
}