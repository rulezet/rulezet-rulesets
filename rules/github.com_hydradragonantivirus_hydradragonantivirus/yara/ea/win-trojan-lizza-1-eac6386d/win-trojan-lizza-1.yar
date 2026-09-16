rule Win_Trojan_Lizza_1
{
strings:
	$a0 = { b118f6061704027505ba3904b108b440cd21b801575a59cd21b43ecd2187cebf5b04c515b8 }


condition:
	$a0
}