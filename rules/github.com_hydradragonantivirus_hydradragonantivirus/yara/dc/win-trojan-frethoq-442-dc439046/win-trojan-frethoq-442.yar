rule Win_Trojan_Frethoq_442
{
strings:
	$a0 = { f8f8fbfdfcfafbfffefff8f8fbfdfcfafbfffefff8f8fbfdfcfafbffeefff8f8091cb608fbb307cc19b0fc49c91b4f67677218686d6c636c5c6c1e625966696c701a5d641e716d661b666a1a3f4e511f65675f }


condition:
	$a0
}