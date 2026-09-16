rule Win_Trojan_Yankee_12
{
strings:
	$a0 = { 5b81ebe302535e81c65003b045b940072e300446e2 }


condition:
	$a0
}