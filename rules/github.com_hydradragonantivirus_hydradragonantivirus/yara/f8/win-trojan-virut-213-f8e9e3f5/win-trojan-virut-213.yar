rule Win_Trojan_Virut_213
{
strings:
	$a0 = { 90e81e00000053b9980c00008bda6631108d141386f28d4002e2f35bc35dc3 }


condition:
	$a0
}