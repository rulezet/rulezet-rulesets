rule Win_Trojan_Sauron_2
{
strings:
	$a0 = { e7eb8bf8d1e7fe81c7feff5bc371fee504e1ef01e1e80af2fc10f2bf1ae2b81cf6b7f6f2e3d6 }


condition:
	$a0
}