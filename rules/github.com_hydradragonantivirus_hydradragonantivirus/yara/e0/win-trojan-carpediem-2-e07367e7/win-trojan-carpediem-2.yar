rule Win_Trojan_CarpeDiem_2
{
strings:
	$a0 = { 8bf4368b2c81ed030144448bc505160150eb2090eb }


condition:
	$a0
}