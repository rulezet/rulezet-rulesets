rule Win_Trojan_N_23
{
strings:
	$a0 = { 8f04e8bcffb440b91800ba4e04e8b1ffc306b413cd2f1e52cd2f5a5b33c08ec026891e8a01 }


condition:
	$a0
}