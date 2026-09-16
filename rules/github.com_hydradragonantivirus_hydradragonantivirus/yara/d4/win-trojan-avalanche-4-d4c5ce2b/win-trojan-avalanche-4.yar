rule Win_Trojan_Avalanche_4
{
strings:
	$a0 = { 66b9f00a0000bb1d02eb06ea2e80370043e2f9 }


condition:
	$a0
}