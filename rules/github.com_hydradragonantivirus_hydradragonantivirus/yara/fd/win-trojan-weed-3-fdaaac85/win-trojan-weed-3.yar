rule Win_Trojan_Weed_3
{
strings:
	$a0 = { 0100bf3262be3e7ed731d28a0442d6153bd3720cef4ba8f1720a499cf3e946ebe6a6f20f3f }


condition:
	$a0
}