rule Win_Trojan_Into_1
{
strings:
	$a0 = { fab000b96606f2ae83ef0458503d004b743180fc3d740e }


condition:
	$a0
}