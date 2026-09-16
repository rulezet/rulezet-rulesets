rule Win_Trojan_Gaboc_1
{
strings:
	$a0 = { 7870737033636f72652e646c6c }

	$a1 = { 6765745f636f72655f696e666f76332e617370 }


condition:
	$a0 and $a1
}