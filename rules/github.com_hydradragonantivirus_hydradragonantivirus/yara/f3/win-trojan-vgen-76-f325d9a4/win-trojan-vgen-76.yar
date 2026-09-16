rule Win_Trojan_VGEN_76
{
strings:
	$a0 = { ffb824008ec01e0e1fb91b01fcf3a4ea1700240033c0508ec026a14c0026a3780326a14e0026a37a0326c7064c }


condition:
	$a0
}