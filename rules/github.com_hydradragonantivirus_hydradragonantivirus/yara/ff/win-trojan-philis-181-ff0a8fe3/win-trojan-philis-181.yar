rule Win_Trojan_Philis_181
{
strings:
	$a0 = { 56535b893c2450562bf05e535383c404893c245033 }


condition:
	$a0
}