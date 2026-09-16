rule Win_Trojan__0385_0005_002_1
{
strings:
	$a0 = { ff5b81c50f02e8ae04b90012b440baf112cd21e81d04b440b91a00ba1012cd21e8d303e8b902b4 }


condition:
	$a0
}