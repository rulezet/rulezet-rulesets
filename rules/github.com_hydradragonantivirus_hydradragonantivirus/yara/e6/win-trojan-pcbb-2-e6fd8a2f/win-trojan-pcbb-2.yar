rule Win_Trojan_PCBB_2
{
strings:
	$a0 = { 120089f7b96506b4eeac32c4aae2fa }


condition:
	$a0
}