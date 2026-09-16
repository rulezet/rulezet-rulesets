rule Win_Trojan_Bancos_652
{
strings:
	$a0 = { 1d533bab43dcf4ef22f3b9f2965c481e812582c517eee4a008198a806c12b5eb622a1c3238325c5fc3c25cebecb2ae30f8aa980ead2134488d88c1f1894a1678378bee6e }


condition:
	$a0
}