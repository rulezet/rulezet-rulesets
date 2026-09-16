rule Win_Trojan_Oxana_4
{
strings:
	$a0 = { 9035cd218cc88ed82b06f703a3f7038cc03d00007564b8 }


condition:
	$a0
}