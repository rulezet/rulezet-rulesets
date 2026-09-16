rule Win_Trojan_Burglar_6
{
strings:
	$a0 = { 1233d2b93403b440cd21b000e83500ba3403b91800b440cd21b42ccd2180f908751fbed902b8 }


condition:
	$a0
}