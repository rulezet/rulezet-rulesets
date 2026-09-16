rule Win_Trojan_Mwin_3
{
strings:
	$a0 = { 5e8a2446568bfeb9[2-3]ac32c4aad0c4fec432e1e2f4c3 }


condition:
	$a0
}