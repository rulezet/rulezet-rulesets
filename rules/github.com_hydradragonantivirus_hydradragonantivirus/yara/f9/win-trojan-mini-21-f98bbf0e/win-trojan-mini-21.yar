rule Win_Trojan_Mini_21
{
strings:
	$a0 = { d2cd212d030097b440508bd5b97f0090cd21b8004233c933d2cd21fdc604e9897c01fc5887d6 }


condition:
	$a0
}