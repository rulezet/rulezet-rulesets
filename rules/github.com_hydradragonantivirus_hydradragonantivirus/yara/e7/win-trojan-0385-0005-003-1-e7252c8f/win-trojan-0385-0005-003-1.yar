rule Win_Trojan__0385_0005_003_1
{
strings:
	$a0 = { 40baf112cd21e81d04b440b91a00ba1012cd21e8d303e8b902b43ecd210e1fb824252ec5160412 }


condition:
	$a0
}