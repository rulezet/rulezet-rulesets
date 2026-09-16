rule Win_Trojan_V_72
{
strings:
	$a0 = { e8910033c933d2b80042e88700ba3e01b90f00b440e87c008b0e39018b163b01b80157e86e00 }


condition:
	$a0
}