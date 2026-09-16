rule Win_Trojan_Patched_125
{
strings:
	$a0 = { 6f756e642e706462[0-80]8a0e84c9740b8d460550ffd783c610ebef8d73468b7b4203fb83c7466a00546a406a2057b8d31a807cffd0 }


condition:
	$a0
}