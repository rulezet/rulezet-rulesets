rule Win_Trojan_Genesis_3
{
strings:
	$a0 = { 4474e7b800438d960402cd215152b801435033c9cd21b8 }


condition:
	$a0
}