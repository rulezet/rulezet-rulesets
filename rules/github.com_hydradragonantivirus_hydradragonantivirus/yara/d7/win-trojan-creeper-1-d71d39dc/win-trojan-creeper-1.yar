rule Win_Trojan_Creeper_1
{
strings:
	$a0 = { 0500018984affeb440b9db018bd6cd21 }


condition:
	$a0
}