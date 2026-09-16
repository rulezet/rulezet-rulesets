rule Win_Trojan_Rage_3
{
strings:
	$a0 = { 741683c63490b9b1018a24518ac8d2c4598824fec046e2f15ec3 }


condition:
	$a0
}