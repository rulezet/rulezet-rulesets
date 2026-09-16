rule Win_Trojan_SmallPox_1
{
strings:
	$a0 = { 212ac0e8ba00b440ba0001b9a402cd21b002e8ab00b440b9c002baa403cd21eb6dc6061b016583 }


condition:
	$a0
}