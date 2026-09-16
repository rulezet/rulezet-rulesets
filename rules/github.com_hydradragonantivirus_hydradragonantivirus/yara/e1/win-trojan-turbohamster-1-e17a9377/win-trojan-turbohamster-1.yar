rule Win_Trojan_TurboHamster_1
{
strings:
	$a0 = { a683f90074c1803d0074bcbe3f0303f5ad2d03002e }


condition:
	$a0
}