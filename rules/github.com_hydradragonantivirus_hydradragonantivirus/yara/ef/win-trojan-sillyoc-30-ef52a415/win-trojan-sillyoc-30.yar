rule Win_Trojan_SillyOC_30
{
strings:
	$a0 = { 01b90000b44ecd210ac0751ab002ba9e00b43dcd218bd8b92e0090ba0000b440cd21b43ecd21b44cb000cd212a2e }


condition:
	$a0
}