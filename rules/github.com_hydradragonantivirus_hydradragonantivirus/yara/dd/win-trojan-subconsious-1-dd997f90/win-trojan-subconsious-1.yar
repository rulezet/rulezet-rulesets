rule Win_Trojan_Subconsious_1
{
strings:
	$a0 = { 3d77427501cf3d004b756c505351521eb8823dcd21 }


condition:
	$a0
}