rule Win_Trojan_Fakealert_59
{
strings:
	$a0 = { ffffff35000000687474703a2f2f736166652d73747269702d646f }


condition:
	$a0
}