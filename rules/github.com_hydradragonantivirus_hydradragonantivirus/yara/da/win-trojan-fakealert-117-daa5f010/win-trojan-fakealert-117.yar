rule Win_Trojan_Fakealert_117
{
strings:
	$a0 = { 558bec6aff68b052420068d031420064a1 }

	$a1 = { 7f7e79787b7a75747776717073726d6c6f6e5d5d5d5d5d }


condition:
	$a0 and $a1
}