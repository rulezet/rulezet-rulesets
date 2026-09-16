rule Win_Trojan_W_281
{
strings:
	$a0 = { b77503b0ffcf3d00ae7403e9970083faff75f83aee75f4601e0e1fb419cd }


condition:
	$a0
}