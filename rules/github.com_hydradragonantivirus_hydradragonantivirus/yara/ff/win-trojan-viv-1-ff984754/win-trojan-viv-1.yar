rule Win_Trojan_VIV_1
{
strings:
	$a0 = { ff1e02005b53b8024233c933d29cfa2eff1e02005b53b80040b90c0233d29cfa2eff1e0200 }


condition:
	$a0
}