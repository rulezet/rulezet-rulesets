rule Win_Trojan_Grog_40
{
strings:
	$a0 = { 3fe9740f803fe8740a59e2d08306fe0003eba78bf3bf76 }


condition:
	$a0
}