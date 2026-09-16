rule Win_Trojan_WhiteNoise_1
{
strings:
	$a0 = { e800008bec8b7600e82a0081ee0301e8130072059090e81f00e857020e0e1f07b80001ffe0b84943 }


condition:
	$a0
}