rule Win_Trojan_Deviant_5
{
strings:
	$a0 = { 0e1fe800005d81ed2a0150558becc74602ff005d8dbe7201b84203d1e88bc88b96b60447478b0533c28905e2f65e81 }


condition:
	$a0
}