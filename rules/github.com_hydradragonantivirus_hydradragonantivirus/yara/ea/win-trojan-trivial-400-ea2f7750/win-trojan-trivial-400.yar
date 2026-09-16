rule Win_Trojan_Trivial_400
{
strings:
	$a0 = { 9e00b80143cd21b44febb7c32042414e414e412c2063 }


condition:
	$a0
}