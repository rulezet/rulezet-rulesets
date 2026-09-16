rule Win_Trojan_Icon_1
{
strings:
	$a0 = { 03015053515256570e1feb00ba6801b44ecd21528d8600008d9e0001b90001bade00be0f00e80000505ab43c8b }


condition:
	$a0
}