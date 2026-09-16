rule Win_Trojan_VGEN_217
{
strings:
	$a0 = { 81ed06008db69b01bf0001fca5a487f5e4403c2e743eeb5a433a5c4155544f455845432e424154000d0a40454348 }


condition:
	$a0
}