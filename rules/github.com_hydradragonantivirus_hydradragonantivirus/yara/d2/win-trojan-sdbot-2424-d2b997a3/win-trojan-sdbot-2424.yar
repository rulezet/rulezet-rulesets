rule Win_Trojan_SdBot_2424
{
strings:
	$a0 = { e8f7feffff05f6120000ffe0e8ebfeffff058d180000ffe0e804000000ffffff }


condition:
	$a0
}