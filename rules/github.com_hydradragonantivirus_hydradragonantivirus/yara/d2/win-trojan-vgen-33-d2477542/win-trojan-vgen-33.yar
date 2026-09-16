rule Win_Trojan_VGEN_33
{
strings:
	$a0 = { cd10b80112b330cd10b81211cd10b44ca01801cd2100 }


condition:
	$a0
}