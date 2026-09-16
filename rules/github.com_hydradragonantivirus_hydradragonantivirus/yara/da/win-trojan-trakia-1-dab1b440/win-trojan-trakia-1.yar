rule Win_Trojan_Trakia_1
{
strings:
	$a0 = { 3d88427505b888429dcf3d9942751c2ec6061a040beb3f }


condition:
	$a0
}