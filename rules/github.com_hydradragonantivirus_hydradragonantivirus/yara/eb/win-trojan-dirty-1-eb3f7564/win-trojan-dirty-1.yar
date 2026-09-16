rule Win_Trojan_Dirty_1
{
strings:
	$a0 = { 5d81ed0301b8cdabcd213dbadc744a1e8cc0488ed8a103002d2200a303001f8b1e020083eb22891e02008cdb03 }


condition:
	$a0
}