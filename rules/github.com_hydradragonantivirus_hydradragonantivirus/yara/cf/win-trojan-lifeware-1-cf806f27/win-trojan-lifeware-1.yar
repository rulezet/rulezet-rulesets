rule Win_Trojan_LifeWare_1
{
strings:
	$a0 = { 6af5e8b9010000a300204000be0c114000e8d7000000e8930100008bf8b02eae75fd87f783c60480 }


condition:
	$a0
}