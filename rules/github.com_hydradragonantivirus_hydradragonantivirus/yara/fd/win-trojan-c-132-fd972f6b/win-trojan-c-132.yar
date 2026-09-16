rule Win_Trojan_C_132
{
strings:
	$a0 = { fab02ef2ae57b84558abaa5f075850529c0ee81b00b8434fabb04daa5a587210b90200b43ccd21 }


condition:
	$a0
}