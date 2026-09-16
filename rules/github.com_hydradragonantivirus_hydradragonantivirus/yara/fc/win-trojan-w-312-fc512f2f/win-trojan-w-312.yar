rule Win_Trojan_W_312
{
strings:
	$a0 = { 733403ca8b4154fe41558d7c02fc8741282b41287e2033c9b19f6033c0f3ae75 }


condition:
	$a0
}