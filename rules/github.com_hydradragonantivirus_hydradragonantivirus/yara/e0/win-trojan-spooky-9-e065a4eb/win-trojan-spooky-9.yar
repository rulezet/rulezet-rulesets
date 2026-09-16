rule Win_Trojan_Spooky_9
{
strings:
	$a0 = { 0500b8004ccd21e2f6c60612020090be2f0189f7b98901e80300e90e00ac9032062e0190aa90e2f590c3 }


condition:
	$a0
}