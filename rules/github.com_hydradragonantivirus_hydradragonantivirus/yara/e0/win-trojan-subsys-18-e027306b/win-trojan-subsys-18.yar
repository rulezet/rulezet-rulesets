rule Win_Trojan_Subsys_18
{
strings:
	$a0 = { f7cf6809c9b1ec10c36e4104c93b9759f57998ccbdc809b1cec716709937ae2303e1f48990875f61d71aabd9987696a2 }


condition:
	$a0
}