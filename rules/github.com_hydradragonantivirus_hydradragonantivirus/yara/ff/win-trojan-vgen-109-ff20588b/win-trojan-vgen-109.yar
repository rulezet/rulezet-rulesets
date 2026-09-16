rule Win_Trojan_VGEN_109
{
strings:
	$a0 = { 06b8cc42cd2181fb3412745f8cd8488ed8c60600005a832e03002d832e12002d8b0e12002bc08ed8c41e84002e89 }


condition:
	$a0
}