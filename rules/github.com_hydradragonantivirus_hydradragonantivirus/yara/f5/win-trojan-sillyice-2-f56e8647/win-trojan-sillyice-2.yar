rule Win_Trojan_SillyIce_2
{
strings:
	$a0 = { 8945fc33c9e86600b8023de863008945feb43f8d55 }


condition:
	$a0
}