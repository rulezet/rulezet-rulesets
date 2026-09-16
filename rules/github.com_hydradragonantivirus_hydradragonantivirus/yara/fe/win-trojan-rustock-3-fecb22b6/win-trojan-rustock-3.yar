rule Win_Trojan_Rustock_3
{
strings:
	$a0 = { eb69ff335a31c283ec048914248f0683ebff83eb }

	$a1 = { 463a5c676d5c746f6a5c[0-12]6f645c617166776c2e706462 }


condition:
	$a0 and $a1
}