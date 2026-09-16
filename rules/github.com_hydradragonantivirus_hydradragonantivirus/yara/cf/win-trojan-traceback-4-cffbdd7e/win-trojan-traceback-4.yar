rule Win_Trojan_Traceback_4
{
strings:
	$a0 = { 19cd2189b45101818451015f088c8c53018884e300e8e3 }


condition:
	$a0
}