rule Win_Trojan_TurboVirus_1
{
strings:
	$a0 = { 5e83ee030e1f8cc089844a07b002e6219c5825fffe509d065633c08ec081c64e07bff004b90f00fcf3aa56b8aa }


condition:
	$a0
}