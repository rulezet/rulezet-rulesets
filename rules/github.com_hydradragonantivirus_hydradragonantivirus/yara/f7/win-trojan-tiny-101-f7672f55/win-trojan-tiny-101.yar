rule Win_Trojan_Tiny_101
{
strings:
	$a0 = { 5e83ee??bf0001a5a433c98ec1bf????380d74 }


condition:
	$a0
}