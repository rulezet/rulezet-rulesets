rule Win_Trojan_Fakealert_125
{
strings:
	$a0 = { 6844474100e8030000b8 }

	$a1 = { 4d6963726f736f667420416e74697669727573 }

	$a2 = { 63003a005c00730065006c002e0074006d0070 }


condition:
	$a0 and $a1 and $a2
}