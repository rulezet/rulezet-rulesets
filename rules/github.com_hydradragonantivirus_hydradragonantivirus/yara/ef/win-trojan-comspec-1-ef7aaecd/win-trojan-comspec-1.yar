rule Win_Trojan_Comspec_1
{
strings:
	$a0 = { 9a000033005589e5b800039a7c02330081ec000331c0a37002bf00000e57b8200050bf44001e579a }


condition:
	$a0
}