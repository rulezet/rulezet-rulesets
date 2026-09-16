rule Win_Trojan_Avcs_1
{
strings:
	$a0 = { e800005b81eb????8beb8db6????568b96????b970008bfe3acafcad33c2ab84e6e2f8c3 }


condition:
	$a0
}