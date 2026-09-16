rule Win_Trojan_Bulgarian123_1
{
strings:
	$a0 = { 038d54f4b440cd21b43ecd21b44fcd2173afbb0001ffe3 }


condition:
	$a0
}