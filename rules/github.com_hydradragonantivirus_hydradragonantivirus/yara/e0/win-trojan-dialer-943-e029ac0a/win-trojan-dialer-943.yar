rule Win_Trojan_Dialer_943
{
strings:
	$a0 = { 558bec6aff6800624000689053400064a1 }

	$a1 = { 5449202050455220534f4c49204144554c5449 }


condition:
	$a0 and $a1
}