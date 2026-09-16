rule Win_Trojan_Small_4347
{
strings:
	$a0 = { 505b505ee9150000002db5591a026a045750 }


condition:
	$a0
}