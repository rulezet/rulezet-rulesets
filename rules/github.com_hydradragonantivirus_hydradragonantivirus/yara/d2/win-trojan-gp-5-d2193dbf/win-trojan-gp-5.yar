rule Win_Trojan_GP_5
{
strings:
	$a0 = { 40cd21720de9cd00b91c00ba2d00b43f }


condition:
	$a0
}