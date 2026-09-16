rule Win_Trojan_Blackhole_31
{
strings:
	$a0 = { 70726f746f747970653b7d636174636828627265627229 }


condition:
	$a0
}