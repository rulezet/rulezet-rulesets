rule Win_Trojan_Amz_2
{
strings:
	$a0 = { b90100d1c250cd2683c4025859e2f0f70641033f007511 }


condition:
	$a0
}