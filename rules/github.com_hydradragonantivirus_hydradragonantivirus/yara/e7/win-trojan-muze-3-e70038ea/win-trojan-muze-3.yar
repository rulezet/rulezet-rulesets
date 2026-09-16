rule Win_Trojan_Muze_3
{
strings:
	$a0 = { 7dfcb97508b44029d2e873fc3d7508752f803e75084db440b907007405bad107cd21b9000081e2 }


condition:
	$a0
}