rule Win_Trojan_QQRob_14
{
strings:
	$a0 = { 446c6c4d757465785f5151526f62626572322e30 }


condition:
	$a0
}