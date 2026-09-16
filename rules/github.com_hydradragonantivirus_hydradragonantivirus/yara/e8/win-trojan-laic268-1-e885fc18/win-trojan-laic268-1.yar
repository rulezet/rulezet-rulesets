rule Win_Trojan_LAIC268_1
{
strings:
	$a0 = { 2400cd21bd0001bf0c01be2400b9e800fce829ffb440b9e800ba0c01cd21b80157595acd21b80143 }


condition:
	$a0
}