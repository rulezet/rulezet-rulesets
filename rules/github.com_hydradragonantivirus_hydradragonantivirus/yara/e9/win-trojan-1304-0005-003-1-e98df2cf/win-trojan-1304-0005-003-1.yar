rule Win_Trojan__1304_0005_003_1
{
strings:
	$a0 = { c9cd21a10f07e83e00ba1707b91c00b440cd2126c74515000026c745170000bafb06b440cd2126 }


condition:
	$a0
}