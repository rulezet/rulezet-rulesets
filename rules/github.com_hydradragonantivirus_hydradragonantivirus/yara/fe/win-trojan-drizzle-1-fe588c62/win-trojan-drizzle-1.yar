rule Win_Trojan_Drizzle_1
{
strings:
	$a0 = { bff890733c3d1b009076362d0300a36b01c6066a01e9ba0001b440b94006e8f6fd721e3d400675 }


condition:
	$a0
}