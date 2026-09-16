rule Win_Trojan_DS_1
{
strings:
	$a0 = { ba0402cd72eb1380c60252b43fb90002ba0005cd723bc15a749cb43ecd72e91aff5c434f4d4d414e442e434f4d004453 }


condition:
	$a0
}