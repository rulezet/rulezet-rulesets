rule Win_Trojan_DarkMatter_1
{
strings:
	$a0 = { 8a042886050146454181f9b6027403e9eeff2be9e970fd }


condition:
	$a0
}