rule Win_Trojan_Totoro_1
{
strings:
	$a0 = { 1ebf02b431ba7100cd219c3df1f17505b8f1f19dcf }


condition:
	$a0
}