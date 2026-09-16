rule Win_Trojan_Simbiot_3
{
strings:
	$a0 = { 83ee035053515256571e069cb8ceaccd213d9719744d8cd8488ed88a26000080fc5a753f33ffb97103a103002d7000 }


condition:
	$a0
}