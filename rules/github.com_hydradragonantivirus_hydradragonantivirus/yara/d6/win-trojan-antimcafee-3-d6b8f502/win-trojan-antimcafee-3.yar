rule Win_Trojan_AntiMcAfee_3
{
strings:
	$a0 = { 6e65742073746f7020224d63416665652e636f6d204d63536869656c6422 }


condition:
	$a0
}