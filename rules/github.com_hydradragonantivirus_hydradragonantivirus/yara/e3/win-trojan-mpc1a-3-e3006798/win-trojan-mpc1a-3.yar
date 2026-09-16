rule Win_Trojan_MPC1a_3
{
strings:
	$a0 = { a5a5c6864c0405b41a8d962104cd21b447b2008db6 }


condition:
	$a0
}