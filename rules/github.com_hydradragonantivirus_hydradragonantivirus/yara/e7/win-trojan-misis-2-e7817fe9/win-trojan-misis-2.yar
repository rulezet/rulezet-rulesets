rule Win_Trojan_Misis_2
{
strings:
	$a0 = { b10750cd13588bf48bfbb1dff3a541cd13b820008ec0 }


condition:
	$a0
}