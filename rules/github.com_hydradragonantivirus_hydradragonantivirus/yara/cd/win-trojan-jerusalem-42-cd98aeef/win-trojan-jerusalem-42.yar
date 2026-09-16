rule Win_Trojan_Jerusalem_42
{
strings:
	$a0 = { 2e8f0602011e2e8f0600010e070e1fbf }


condition:
	$a0
}