rule Win_Trojan_Antipas_1
{
strings:
	$a0 = { 1e06b8cdabcd213dbadc743e8cd8488ec026832e030045832e0200458e0602000e1f33ff8bf5b94d04fcf3a4 }


condition:
	$a0
}