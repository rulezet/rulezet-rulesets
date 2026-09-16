rule Win_Trojan_Squisher_2
{
strings:
	$a0 = { 8ec0268a1db95401575156f2a4ea31014400f9 }


condition:
	$a0
}