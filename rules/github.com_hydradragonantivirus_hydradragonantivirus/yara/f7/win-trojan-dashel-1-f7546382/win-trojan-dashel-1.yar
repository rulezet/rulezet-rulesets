rule Win_Trojan_Dashel_1
{
strings:
	$a0 = { 02002d50008ed88ed0bcfc040ee80000fb5f83ef13578bf71e0690b9fe065603f12eff045e83c102515133c0d1 }


condition:
	$a0
}