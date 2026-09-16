rule Win_Trojan_Zorm_2
{
strings:
	$a0 = { eb02909033d2b91100b43dcd2104febb00002e300743e2fa902ec6061801c3bb0000b0 }


condition:
	$a0
}