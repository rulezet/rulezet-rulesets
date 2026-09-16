rule Win_Trojan_Navigator_1
{
strings:
	$a0 = { ba1efecd213e8986ea0193b80057cd213e8996ec01 }


condition:
	$a0
}