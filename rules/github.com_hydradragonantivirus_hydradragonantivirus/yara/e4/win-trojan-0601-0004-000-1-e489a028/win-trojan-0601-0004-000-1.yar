rule Win_Trojan__0601_0004_000_1
{
strings:
	$a0 = { ff8bf7b9110351f3a4e87300b440592bd2cd215e1fb000e85500b43ffec4b91c008bd6cd21595a }


condition:
	$a0
}