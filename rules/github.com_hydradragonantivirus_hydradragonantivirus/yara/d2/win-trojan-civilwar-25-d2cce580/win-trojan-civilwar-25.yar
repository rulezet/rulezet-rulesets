rule Win_Trojan_CivilWar_25
{
strings:
	$a0 = { e83b002d03003e8986f501b80042e82d00e84400b80242e82400b440b9f4008d960301cd21 }


condition:
	$a0
}