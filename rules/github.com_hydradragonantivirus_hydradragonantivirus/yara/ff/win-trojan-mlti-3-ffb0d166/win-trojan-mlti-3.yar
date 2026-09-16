rule Win_Trojan_MLTI_3
{
strings:
	$a0 = { b93e030e1f33d2cd21fa5a1f7200b43ecd21fa }


condition:
	$a0
}