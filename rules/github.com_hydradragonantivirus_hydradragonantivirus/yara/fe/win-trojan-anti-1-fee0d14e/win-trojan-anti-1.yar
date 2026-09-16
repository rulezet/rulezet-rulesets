rule Win_Trojan_Anti_1
{
strings:
	$a0 = { e86700be9f03e83b028b4cfe83e10383c103b901008344fe0451e8b400593c007502e2f5e80f00817cfe00037600e8 }


condition:
	$a0
}