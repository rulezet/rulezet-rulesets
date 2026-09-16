rule Win_Trojan_Leprosy_35
{
strings:
	$a0 = { 0100c3bb32018a27903226060188274381fb4f047ef0c3 }


condition:
	$a0
}