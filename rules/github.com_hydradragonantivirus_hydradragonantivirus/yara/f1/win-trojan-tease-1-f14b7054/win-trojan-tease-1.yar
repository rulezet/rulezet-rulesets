rule Win_Trojan_Tease_1
{
strings:
	$a0 = { 01cd21e80100c38b8613018db63901b9f70131044646e2fac3 }


condition:
	$a0
}