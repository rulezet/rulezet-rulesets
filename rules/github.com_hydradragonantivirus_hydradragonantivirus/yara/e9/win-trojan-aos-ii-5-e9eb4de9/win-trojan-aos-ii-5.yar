rule Win_Trojan_AOS_II_5
{
strings:
	$a0 = { cd2000505992929292929292b9aa01bb22002e8107000083c30283e90175f3 }


condition:
	$a0
}