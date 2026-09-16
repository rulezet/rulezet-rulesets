rule Win_Trojan_VLAD_2
{
strings:
	$a0 = { 4f8edf33ff803d5a7531c6054d836d0326836d12268e45120e1ffcbef601b108f3a5be0001b1 }


condition:
	$a0
}