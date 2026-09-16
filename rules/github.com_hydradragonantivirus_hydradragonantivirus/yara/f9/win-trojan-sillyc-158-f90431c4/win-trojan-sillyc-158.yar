rule Win_Trojan_SillyC_158
{
strings:
	$a0 = { 01f3a48d962602b41acd21b42acd213c00750f8d96c30150b80009cd2158b44ccd21b44e8d }


condition:
	$a0
}