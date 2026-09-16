rule Win_Trojan_VGEN_729
{
strings:
	$a0 = { bd0700b8dd54cd2139d874418cc08ccb488ed8a103002d250001c326891e0200a30300061f83eb108ec3bf00018d33b9 }


condition:
	$a0
}