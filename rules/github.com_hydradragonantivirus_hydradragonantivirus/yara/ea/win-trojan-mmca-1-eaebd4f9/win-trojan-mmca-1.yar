rule Win_Trojan_MMCA_1
{
strings:
	$a0 = { 7503e98b0081c600018936ed0133d2b440b9f901cd21 }


condition:
	$a0
}