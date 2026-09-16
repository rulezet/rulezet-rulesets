rule Win_Trojan_Y_8
{
strings:
	$a0 = { e800005e83ee0333c08ec08ed8bf0002e82500ea18020000be4c00bf7402a5a5897cfc894cfeb801 }


condition:
	$a0
}