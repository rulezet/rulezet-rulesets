rule Win_Trojan_SillyC_55
{
strings:
	$a0 = { ed0601b903008db69d01bf000157f3a48d96a301b41acd21b44e8d969701b90700cd217303eb6090b8023d8d96c1 }


condition:
	$a0
}