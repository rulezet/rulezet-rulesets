rule Win_Trojan_Packed_40
{
strings:
	$a0 = { 665b6693665066536658665b6693eb }

	$a1 = { 665066536658665b66 }


condition:
	$a0 and $a1
}