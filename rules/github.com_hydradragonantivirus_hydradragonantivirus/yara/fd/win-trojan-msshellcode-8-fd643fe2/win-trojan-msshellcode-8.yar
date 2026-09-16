rule Win_Trojan_MSShellcode_8
{
strings:
	$a0 = { fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f05257 }


condition:
	$a0
}