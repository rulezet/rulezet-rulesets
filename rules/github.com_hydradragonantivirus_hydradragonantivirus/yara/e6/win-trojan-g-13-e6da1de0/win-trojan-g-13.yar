rule Win_Trojan_G_13
{
strings:
	$a0 = { b90c012e8107000083c302e2f6e800005d81ed1300061eb84144cd213d53507456b44abbffffcd2183eb48b44a }


condition:
	$a0
}