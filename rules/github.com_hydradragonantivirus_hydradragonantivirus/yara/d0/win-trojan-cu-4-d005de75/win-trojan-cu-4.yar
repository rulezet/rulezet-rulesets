rule Win_Trojan_CU_4
{
strings:
	$a0 = { 3104434f2d03002ea32c03050300b440ba0000b93404cd21b8004233c999cd21b440ba2b03 }


condition:
	$a0
}