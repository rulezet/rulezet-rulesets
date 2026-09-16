rule Win_Trojan__0064_0006_001_1
{
strings:
	$a0 = { 598d968b05cd2132c0e829008d96eb04cd215a5980e1e080c91fb80157cd211f5a59e80600b4 }


condition:
	$a0
}