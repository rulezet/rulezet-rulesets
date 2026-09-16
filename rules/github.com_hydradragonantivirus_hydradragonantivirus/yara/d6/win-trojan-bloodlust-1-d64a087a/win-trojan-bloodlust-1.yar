rule Win_Trojan_Bloodlust_1
{
strings:
	$a0 = { 32c3aae2fa2e833e0f01007429b4402e8b1e0f012eff360f }


condition:
	$a0
}