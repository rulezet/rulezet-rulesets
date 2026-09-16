rule Win_Trojan_Gen_26
{
strings:
	$a0 = { 96f301b90500b440cd218b1481c20301b91207908dbe9c088db60a01e86600b440cd218f86fd01 }


condition:
	$a0
}