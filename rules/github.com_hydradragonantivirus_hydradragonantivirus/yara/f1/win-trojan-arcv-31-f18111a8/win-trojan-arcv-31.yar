rule Win_Trojan_ARCV_31
{
strings:
	$a0 = { be1601b9bc012e812c000083c6024975f5 }


condition:
	$a0
}