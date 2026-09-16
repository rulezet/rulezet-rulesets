rule Win_Trojan_Sink_2
{
strings:
	$a0 = { e800005e83ee048b846c01a302018b846a01a30001b800ffcd213dff00743ab82135cd21899c5b018c845d018cc848 }


condition:
	$a0
}