rule Win_Trojan_Bancos_651
{
strings:
	$a0 = { ff6068cda93c369116b2f6ec5ce75e2bedec22f5fb685ac53f02d6760dca04caa06204dfa01d0bfc52b63133ee85be6bd25608b9c8e0c7c4ae59d448617e39f34b2d96c6 }


condition:
	$a0
}