rule Win_Trojan_B_51
{
strings:
	$a0 = { 13b40432c9cd1a80f95a7607263a161707740a268816170726fe06160706b8000250cb }


condition:
	$a0
}