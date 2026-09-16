rule Win_Trojan_Polonaise_1
{
strings:
	$a0 = { 2e890783c3042ea119012eff372e8907ba0001b440b962092e8b1e1101e81500bb4d0a4358 }


condition:
	$a0
}