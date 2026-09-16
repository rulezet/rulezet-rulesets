rule Win_Trojan_McRat_1
{
strings:
	$a0 = { 8b3d142040008d4c00028b45fc8d9594fbffff51526a0253689431400050ffd78d8d84efffff51ffd68b4dfc8d5400028d8584efffff52506a025368dc30400051ffd7 }


condition:
	$a0
}