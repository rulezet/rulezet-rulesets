rule Win_Trojan_Witam_2
{
strings:
	$a0 = { 14c7003d20a17208bf00ad3397c20197751f1d14ab14cd4747149714d4d3d11483b3eae15d }


condition:
	$a0
}