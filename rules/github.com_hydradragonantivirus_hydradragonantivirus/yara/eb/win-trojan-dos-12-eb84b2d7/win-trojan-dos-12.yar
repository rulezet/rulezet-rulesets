rule Win_Trojan_Dos_12
{
strings:
	$a0 = { be13012e8a840101b9fa00e8 }

	$a1 = { 2e300446e2fac3 }


condition:
	$a0 and $a1
}