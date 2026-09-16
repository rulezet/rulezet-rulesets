rule Win_Trojan_Moon_1
{
strings:
	$a0 = { fc73cc3d060272c7fec4a30201b440baf00190b9130090cd21b8004233c933d2cd21b43f8bd5 }


condition:
	$a0
}