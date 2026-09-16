rule Win_Trojan_Qark_3
{
strings:
	$a0 = { 40b93300ba5a02cd21b440b95a01ba0001cd21b440b93800ba9206cd21b440b90400ba8e02cd21 }


condition:
	$a0
}