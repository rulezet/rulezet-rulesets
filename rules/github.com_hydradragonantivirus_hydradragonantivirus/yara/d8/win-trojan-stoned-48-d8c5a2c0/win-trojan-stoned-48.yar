rule Win_Trojan_Stoned_48
{
strings:
	$a0 = { 7cb82e00a34c008c064e00b9be01be007c31fffcf3a42eff2e1e7c31c08ec0cd130e1fb80102 }


condition:
	$a0
}