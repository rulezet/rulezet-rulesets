rule Win_Spyware_SpyEyes_102
{
strings:
	$a0 = { 5213daf7d213f8c3 }


condition:
	$a0
}