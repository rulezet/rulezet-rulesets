rule Win_Trojan_ErrorInc_2
{
strings:
	$a0 = { 01b440cd21e85a00b43ecd21b44fcd217203e976ffbf }


condition:
	$a0
}