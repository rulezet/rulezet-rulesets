rule Win_Trojan_Philis_146
{
strings:
	$a0 = { 6053bb5420220881c321e8f24933 }


condition:
	$a0
}