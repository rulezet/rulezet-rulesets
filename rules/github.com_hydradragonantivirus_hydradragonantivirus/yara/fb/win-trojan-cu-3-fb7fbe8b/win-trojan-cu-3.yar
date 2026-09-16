rule Win_Trojan_CU_3
{
strings:
	$a0 = { 7503434f2d03002ea37a02050300b440ba0000b97703cd21b8004233c999cd21b440ba7902 }


condition:
	$a0
}