rule Win_Trojan_Sirius_36
{
strings:
	$a0 = { d9b9fafdf7d981372d734343e2f8c5732d2eac9e387333759572d7c9682ae06595401dcce774e052ac8de7745921a1ab65fdf5f20370 }


condition:
	$a0
}