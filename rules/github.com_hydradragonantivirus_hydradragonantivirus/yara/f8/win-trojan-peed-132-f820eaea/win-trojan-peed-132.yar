rule Win_Trojan_Peed_132
{
strings:
	$a0 = { 90e8000000008d64240344e8710000005589e5ad83ee014e4e4ec9c20800f7da29 }


condition:
	$a0
}