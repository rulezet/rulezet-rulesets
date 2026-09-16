rule Win_Trojan_Icabdi_1
{
strings:
	$a0 = { 433a5c5c746573742e626174 }

	$a1 = { 22433a5c5c494341422e444d50222c22433a5c5c694361622e65786522 }


condition:
	$a0 and $a1
}