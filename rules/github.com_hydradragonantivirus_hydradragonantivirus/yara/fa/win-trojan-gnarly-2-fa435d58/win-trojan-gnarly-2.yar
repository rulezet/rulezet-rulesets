rule Win_Trojan_Gnarly_2
{
strings:
	$a0 = { 72656d6f746520636f6e74726f6c[0-93]5c436f6d6d616e64732e747874[0-3]5c4e6f74657061642e657865 }


condition:
	$a0
}