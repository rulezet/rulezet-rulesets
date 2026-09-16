rule Win_Trojan_LOL_1
{
strings:
	$a0 = { e4024d5a74dd2d03002ea3e80233 }


condition:
	$a0
}