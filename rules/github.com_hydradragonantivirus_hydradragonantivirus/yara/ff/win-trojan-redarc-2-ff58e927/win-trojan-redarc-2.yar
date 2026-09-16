rule Win_Trojan_Redarc_2
{
strings:
	$a0 = { 06e80000975d83ed078bc51e05150050cbeabb0011b44acd217307071f610e56cb9ab8680403 }


condition:
	$a0
}