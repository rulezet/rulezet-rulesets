rule Win_Trojan_Linc_2
{
strings:
	$a0 = { 7504b8ffffcf3d004b757b5053b443cd217271b8 }


condition:
	$a0
}