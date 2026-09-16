rule Win_Trojan_Mission_1
{
strings:
	$a0 = { cdfe0e078bf3bf030003f7b93b00fcf3a48bf3bfbe0103f7b11dfcf3a5b8010333db41cdfe071f }


condition:
	$a0
}