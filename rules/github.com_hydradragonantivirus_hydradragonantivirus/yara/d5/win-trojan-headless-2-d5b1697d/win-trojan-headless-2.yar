rule Win_Trojan_Headless_2
{
strings:
	$a0 = { 8ed8be0000e82100b202e83100e82e00e82b00fec280fa0875f0be4d00e80900be0201e80300eb26905052ac0a }


condition:
	$a0
}