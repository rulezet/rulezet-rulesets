rule Win_Trojan_NMSG_2
{
strings:
	$a0 = { 3d1ae033c9ba1e00161fcd218bd85872158b0e1a00061f33d28ae09eb43f12e2cd21b43ecd21 }


condition:
	$a0
}