rule Win_Trojan_Adolph_1
{
strings:
	$a0 = { 742380fc417407e93a015807ebf9065033c08ec026 }


condition:
	$a0
}