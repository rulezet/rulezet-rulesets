rule Win_Trojan_Retaliator_2
{
strings:
	$a0 = { 33c08bf083c6038a04345688044681fed605740d8a0434ab88044681fed60575e6c3 }


condition:
	$a0
}