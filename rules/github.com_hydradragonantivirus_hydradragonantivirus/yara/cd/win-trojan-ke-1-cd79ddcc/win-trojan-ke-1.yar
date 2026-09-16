rule Win_Trojan_KE_1
{
strings:
	$a0 = { 87440ca38f00be1800bf9c02e877feb475cc5a1f59e85cfe5a1fb8616ecc5a1fb003cd2107 }


condition:
	$a0
}