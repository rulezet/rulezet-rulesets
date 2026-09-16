rule Win_Trojan_Vgen_78
{
strings:
	$a0 = { cd213c02730533c00650cbbf5c018b3602002bf781fe00107203be0010fa8ed781c4be06fb7312161f0ee8590233 }


condition:
	$a0
}