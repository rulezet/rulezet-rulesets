rule Win_Trojan_BadAttitude_1
{
strings:
	$a0 = { e80100c38b861c018db64201b9490131044646e2fac3 }


condition:
	$a0
}