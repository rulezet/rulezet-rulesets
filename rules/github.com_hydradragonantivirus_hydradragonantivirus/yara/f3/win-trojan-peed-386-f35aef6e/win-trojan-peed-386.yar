rule Win_Trojan_Peed_386
{
strings:
	$a0 = { 8d0438054e5200003d4e52000074573d2cf100007f505589e587fb0f6fc587df }


condition:
	$a0
}