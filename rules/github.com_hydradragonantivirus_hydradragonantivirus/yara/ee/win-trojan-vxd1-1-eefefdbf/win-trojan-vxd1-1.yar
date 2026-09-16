rule Win_Trojan_VXD1_1
{
strings:
	$a0 = { cd29f9c3f8c360b43f8b1ed204cd2161c360b4408b1ed204cd2161c36603161c056066525a59 }


condition:
	$a0
}