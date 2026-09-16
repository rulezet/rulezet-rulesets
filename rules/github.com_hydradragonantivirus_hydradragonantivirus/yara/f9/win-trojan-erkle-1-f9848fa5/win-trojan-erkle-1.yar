rule Win_Trojan_Erkle_1
{
strings:
	$a0 = { b8020050e8af0783c40a5633c033d25052b8140050b8030050e89a0783c40ab8c20050e80d0259 }


condition:
	$a0
}