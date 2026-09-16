rule Win_Trojan_Bancos_847
{
strings:
	$a0 = { 68747470733a2f2f7777772e6a6170616e6e657462616e6b2e636f2e6a702f6c6f67696e2e68746d6c }


condition:
	$a0
}