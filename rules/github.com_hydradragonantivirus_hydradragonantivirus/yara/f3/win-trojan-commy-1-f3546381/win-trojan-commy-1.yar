rule Win_Trojan_Commy_1
{
strings:
	$a0 = { 3d0181c66a01b9cf01300446e2fb5e5681c64603b9c401300446e2fb }


condition:
	$a0
}