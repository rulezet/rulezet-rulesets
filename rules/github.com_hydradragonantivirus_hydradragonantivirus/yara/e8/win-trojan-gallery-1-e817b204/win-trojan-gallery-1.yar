rule Win_Trojan_Gallery_1
{
strings:
	$a0 = { cd213c047303e99400e800005d83ed0fb8fe52cd213d52fe268b47fe898620027503eb79900e1f0e07b448bb29 }


condition:
	$a0
}