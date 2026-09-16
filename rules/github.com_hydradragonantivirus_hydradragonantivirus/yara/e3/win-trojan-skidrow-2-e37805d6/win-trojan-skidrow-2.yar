rule Win_Trojan_SkidRow_2
{
strings:
	$a0 = { cd21b452cd2126c57712c5341e8cd84050fcb902008b }


condition:
	$a0
}