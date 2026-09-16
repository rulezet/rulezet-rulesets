rule Win_Trojan_YB_5
{
strings:
	$a0 = { cd2193b905008d940801b43fcd2172218b842b0105 }


condition:
	$a0
}