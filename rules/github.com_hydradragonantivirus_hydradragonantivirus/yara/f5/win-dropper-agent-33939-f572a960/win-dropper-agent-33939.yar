rule Win_Dropper_Agent_33939
{
strings:
	$a0 = { 737663686f73742e6578 }

	$a1 = { 415445494e464f00000000ffffffff110000005c[0-10]5c47686f6f6b2e646c6c000000 }


condition:
	$a0 and $a1
}