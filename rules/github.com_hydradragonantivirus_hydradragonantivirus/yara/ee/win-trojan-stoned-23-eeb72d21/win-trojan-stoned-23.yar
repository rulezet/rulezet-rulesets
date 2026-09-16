rule Win_Trojan_Stoned_23
{
strings:
	$a0 = { 0e7b00b8010350cdaa5872c4b92100bfbe01bebe03f3a531db4188367d00cdaacc2ea37b00cdaa }


condition:
	$a0
}