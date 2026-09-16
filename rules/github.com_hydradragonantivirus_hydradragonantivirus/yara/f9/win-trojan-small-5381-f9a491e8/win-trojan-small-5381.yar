rule Win_Trojan_Small_5381
{
strings:
	$a0 = { b810000087c1c03250e8??000000 }


condition:
	$a0
}