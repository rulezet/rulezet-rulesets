rule Win_Trojan_Swine_2
{
strings:
	$a0 = { 03031d0ca99e8135333003c41a41c641de0ca99dd0ee9e241fe996c8be1a1b6c16c8e7771cfad0ee }


condition:
	$a0
}