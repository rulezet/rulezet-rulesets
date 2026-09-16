rule Win_Trojan_Waledac_16
{
strings:
	$a0 = { 558bec83ec648b0da99a41008d35f2fc4e0003ce }


condition:
	$a0
}