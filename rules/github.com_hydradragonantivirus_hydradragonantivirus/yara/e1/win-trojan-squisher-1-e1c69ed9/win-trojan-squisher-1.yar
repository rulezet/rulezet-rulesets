rule Win_Trojan_Squisher_1
{
strings:
	$a0 = { bf0c00b11b3d00057202b126ad3cda7502b07803c1aba5bf4c00ff35b86b01abff358cc8ab }


condition:
	$a0
}