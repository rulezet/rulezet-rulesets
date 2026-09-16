rule Win_Trojan_Peed_229
{
strings:
	$a0 = { 87f7b854680000730b405aff1543680500ff5500 }


condition:
	$a0
}