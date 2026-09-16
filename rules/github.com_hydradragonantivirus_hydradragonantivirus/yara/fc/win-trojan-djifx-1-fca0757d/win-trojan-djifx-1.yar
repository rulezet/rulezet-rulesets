rule Win_Trojan_DJIFX_1
{
strings:
	$a0 = { 12072efe45f92e8aa412072e3084120786c446e2e4 }


condition:
	$a0
}