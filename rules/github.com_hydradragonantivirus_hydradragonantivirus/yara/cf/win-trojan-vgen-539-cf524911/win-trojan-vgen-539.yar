rule Win_Trojan_VGEN_539
{
strings:
	$a0 = { 9090b8000026a38f0226a3910226a29302b413cd152ea2e602b42fb60004018ad02ebee802cd15b40eb200cd153c01 }


condition:
	$a0
}