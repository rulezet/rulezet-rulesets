rule Win_Trojan__0112_0004_001_1
{
strings:
	$a0 = { 4059ba3a04cd2132c0e83100ba1b04cd215a5980e1e080c900b80157cd211f5a59e80f00b4 }


condition:
	$a0
}