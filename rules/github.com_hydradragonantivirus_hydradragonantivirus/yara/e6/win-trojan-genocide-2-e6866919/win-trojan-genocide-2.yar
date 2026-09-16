rule Win_Trojan_Genocide_2
{
strings:
	$a0 = { 8b9c790481c65e01b91203d1e973014e8bfead33c3abe2fa }


condition:
	$a0
}