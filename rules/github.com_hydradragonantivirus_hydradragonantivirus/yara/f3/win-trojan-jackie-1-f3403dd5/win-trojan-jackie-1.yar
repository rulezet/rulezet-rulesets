rule Win_Trojan_Jackie_1
{
strings:
	$a0 = { 636b6965325d202e2e209a00006f005589e5b800029acd026f0081ec0002c606501801c60656 }


condition:
	$a0
}