rule Win_Trojan_Trivial_32
{
strings:
	$a0 = { 4fba8000cd2172f6b10dbf9e00f2ae807dfc437513b8023db29ecd2172e193b440ba0001b13fcd }


condition:
	$a0
}