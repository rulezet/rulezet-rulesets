rule Win_Trojan_Mantis_2
{
strings:
	$a0 = { c0ba6202b815ff2eff3614018becf7d52e8f061401e800005e81ee1c0187f5e82600eb72900000e5403d000074f989 }


condition:
	$a0
}