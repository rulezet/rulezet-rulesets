rule Win_Trojan_Elojo_1
{
strings:
	$a0 = { fa77db3dd00776d65026c7451500002d0300a38f00b440b90400ba8e00cd213d000074ba5826 }


condition:
	$a0
}