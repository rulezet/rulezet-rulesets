rule Win_Trojan_JS_280
{
strings:
	$a0 = { 6877742c745f702b3a2b2f5f[0-26]2f777a302e2c682c74306d77222e7265706c }


condition:
	$a0
}