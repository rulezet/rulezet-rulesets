rule Win_Trojan_Pakes_983
{
strings:
	$a0 = { 60b82e646c6cba6e746c61b96e7569326a005051528bc46a006a0050e8????????83f8017c1066b9504503403c663308 }


condition:
	$a0
}