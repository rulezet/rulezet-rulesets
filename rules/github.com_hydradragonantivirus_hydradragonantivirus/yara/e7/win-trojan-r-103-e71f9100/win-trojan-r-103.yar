rule Win_Trojan_R_103
{
strings:
	$a0 = { 33c08ed0[7]be007cbf0006b90002fcf3a450681c06cbfb60b9??01bd }


condition:
	$a0
}