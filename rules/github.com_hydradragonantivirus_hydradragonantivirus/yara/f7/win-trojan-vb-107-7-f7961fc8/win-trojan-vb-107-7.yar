rule Win_Trojan_VB_107_7
{
strings:
	$a0 = { 72ffb7ffff736f722046636c734f506c7567696e0022693422212687ab71377f419e9df1eda055 }


condition:
	$a0
}