rule Win_Trojan_Hole_1
{
strings:
	$a0 = { 8bec8b6efa81ed0d00fbb80012cd2f3cff1aedb1018dbe2b00b090f3aa90b9c7018db63900 }


condition:
	$a0
}