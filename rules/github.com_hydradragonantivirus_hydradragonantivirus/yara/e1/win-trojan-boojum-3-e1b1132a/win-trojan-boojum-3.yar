rule Win_Trojan_Boojum_3
{
strings:
	$a0 = { 3d004b75105689d646803c0075fa807cff4574075e9dea }


condition:
	$a0
}