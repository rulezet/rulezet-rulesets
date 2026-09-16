rule Win_Trojan_CodeBreaker_1
{
strings:
	$a0 = { 40cb446d43407ec9c6d945f84002738973928d61f400cdd6d845f943408d61ab43a90841f8420273 }


condition:
	$a0
}