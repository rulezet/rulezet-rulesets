rule Win_Trojan_SillyORC_9
{
strings:
	$a0 = { 8ec0bf44028bec8b76008bee81c64100b90a00f3a6c3000000003d004b75101e529c2eff1e40025a1f9ce807009d }


condition:
	$a0
}