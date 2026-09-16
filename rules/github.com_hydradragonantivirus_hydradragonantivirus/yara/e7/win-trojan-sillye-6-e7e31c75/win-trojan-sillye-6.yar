rule Win_Trojan_SillyE_6
{
strings:
	$a0 = { c88ed88b362e018b3e300132e4cd1a83c24089163f01eb4190b43bba3201cd21b44eb91000ba3b01cd21b44fcd2172 }


condition:
	$a0
}