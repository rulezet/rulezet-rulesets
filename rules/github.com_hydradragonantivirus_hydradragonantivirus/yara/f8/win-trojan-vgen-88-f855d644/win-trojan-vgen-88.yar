rule Win_Trojan_VGEN_88
{
strings:
	$a0 = { c08ed8be4c00bf006aa5a50e1fbb80008a073c02721a90908a47020c203c61720f90903c63730990902c61a26f6beb }


condition:
	$a0
}