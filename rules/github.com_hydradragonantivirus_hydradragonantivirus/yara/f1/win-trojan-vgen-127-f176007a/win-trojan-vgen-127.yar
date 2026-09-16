rule Win_Trojan_Vgen_127
{
strings:
	$a0 = { 01b409cd21fcb430cd2186c4ba4c0480fc027255bc4a1db44abb0010cd21a1210403062304a3ed03b448bb0010cd }


condition:
	$a0
}