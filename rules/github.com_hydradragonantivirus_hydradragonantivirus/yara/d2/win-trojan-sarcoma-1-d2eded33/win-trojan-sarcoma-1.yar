rule Win_Trojan_Sarcoma_1
{
strings:
	$a0 = { 5e83ee0ab85757cd213c7574671e8cd8488ed88a16 }


condition:
	$a0
}