rule Win_Trojan_Ieronim_4
{
strings:
	$a0 = { 51b9a36581e9cb622e81375a4281c348cb81eb46cbe2f159c3 }


condition:
	$a0
}