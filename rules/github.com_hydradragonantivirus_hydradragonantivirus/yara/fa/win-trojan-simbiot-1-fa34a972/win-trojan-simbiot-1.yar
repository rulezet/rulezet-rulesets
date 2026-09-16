rule Win_Trojan_Simbiot_1
{
strings:
	$a0 = { ee035053515256571e069cb8ceaccd213d9719744d8cd8488ed88a26000080fc5a753f33ffb96b03a103002d6f00 }


condition:
	$a0
}