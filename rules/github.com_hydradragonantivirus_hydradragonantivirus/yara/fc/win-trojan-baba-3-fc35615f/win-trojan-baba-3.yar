rule Win_Trojan_Baba_3
{
strings:
	$a0 = { 5e1e06568cc88ec08ed8bf000181c64301b90400fcf3a45eb8babacd213dccfa7502eb4d07068cc0488ec026 }


condition:
	$a0
}