rule Win_Dropper_Agent_33920
{
strings:
	$a0 = { 8bd8538d4da8ba786a4000b88c6a4000e820ecffff8b45a8e88cd4ffff50a1b0704000e881d4ffff8bc8b8010000805ae854e2ffff6a0553e888e1ffffe817f9ffffe89ed0ffff }


condition:
	$a0
}