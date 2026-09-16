rule Win_Trojan_MPC1a_2
{
strings:
	$a0 = { a5a5a5c686080602b41a8d96dd05cd21b447b2008db6 }


condition:
	$a0
}