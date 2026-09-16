rule Win_Trojan_Nax_1
{
strings:
	$a0 = { e800005e83ee06562e83bc66050074299090908cc88ec0bf3c0003fe2e8b8c68052e8a846b05b40080f4392630 }


condition:
	$a0
}