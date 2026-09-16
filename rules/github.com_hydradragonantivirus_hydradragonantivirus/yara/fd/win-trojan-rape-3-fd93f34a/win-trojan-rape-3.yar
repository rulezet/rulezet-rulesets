rule Win_Trojan_Rape_3
{
strings:
	$a0 = { 36078bfe56501e060e1f0e07b200b93307ac5188d1d2c8fec259aae2f4 }


condition:
	$a0
}