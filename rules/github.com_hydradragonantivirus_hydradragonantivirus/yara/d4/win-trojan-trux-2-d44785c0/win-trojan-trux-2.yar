rule Win_Trojan_Trux_2
{
strings:
	$a0 = { 01cd16740403fe03effae81d058bec3e8b6efefb81ed0e01e9dd01576861743f3f3f205472757865737465643f3f3f }


condition:
	$a0
}