rule Win_Trojan_SillyC_92
{
strings:
	$a0 = { fea1ba01a3bc01ba00feb41acd21b42acd213c00740580fa0d75198d16be01e87f0072698bd7b441cd218d16be01 }


condition:
	$a0
}