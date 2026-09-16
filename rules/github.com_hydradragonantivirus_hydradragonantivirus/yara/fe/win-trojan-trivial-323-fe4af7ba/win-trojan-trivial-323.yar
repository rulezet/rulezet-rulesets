rule Win_Trojan_Trivial_323
{
strings:
	$a0 = { 3f00cd217301c3ba9e00b8c23dcd21721393b93a008bf4ad2d030092b440cd21b43ecd21b44fcd }


condition:
	$a0
}