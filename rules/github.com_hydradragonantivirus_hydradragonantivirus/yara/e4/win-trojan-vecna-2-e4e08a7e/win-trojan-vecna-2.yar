rule Win_Trojan_Vecna_2
{
strings:
	$a0 = { 434fc745024d00b45bb90300ba9e00cd21720f93b440b92d01ba0001cd21b43ecd21b44febcc }


condition:
	$a0
}