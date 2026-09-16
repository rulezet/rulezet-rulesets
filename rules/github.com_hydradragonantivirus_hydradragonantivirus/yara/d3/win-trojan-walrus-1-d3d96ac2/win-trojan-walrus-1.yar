rule Win_Trojan_Walrus_1
{
strings:
	$a0 = { 3c4d7421b80242e8a3ffa31801b9e201b44099cd21b80042e892ffba1701b90300b440cd215a58 }


condition:
	$a0
}