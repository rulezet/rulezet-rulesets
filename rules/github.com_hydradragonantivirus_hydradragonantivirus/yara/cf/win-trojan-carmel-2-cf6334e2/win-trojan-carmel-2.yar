rule Win_Trojan_Carmel_2
{
strings:
	$a0 = { 13048bfead48abc1e0068ec08bf48ccfe86200b9f800f2a4bb3000eb0ee8ac00b80102bb007cb6 }


condition:
	$a0
}