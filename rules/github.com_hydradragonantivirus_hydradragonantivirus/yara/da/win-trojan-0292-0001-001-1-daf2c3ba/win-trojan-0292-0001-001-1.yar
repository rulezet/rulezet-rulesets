rule Win_Trojan__0292_0001_001_1
{
strings:
	$a0 = { 2ea32201b4402e8b1e1d01b90400ba2101cd21b43e2e8b1e1d01cd21b801432e8b0e1b01ba0a01 }


condition:
	$a0
}