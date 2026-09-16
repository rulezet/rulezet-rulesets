rule Win_Trojan_Hupigon_44
{
strings:
	$a0 = { 506870694a00e8050bf6ff85c00f94c084c07411c60588cf4a0000e808f9ffff }


condition:
	$a0
}