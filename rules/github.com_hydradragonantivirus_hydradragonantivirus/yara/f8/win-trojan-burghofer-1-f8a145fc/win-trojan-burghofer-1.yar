rule Win_Trojan_Burghofer_1
{
strings:
	$a0 = { 8e06120033ff8bf30e1fb90d02f3a4 }


condition:
	$a0
}