rule Win_Trojan_Grog_5
{
strings:
	$a0 = { 35b440cd2172f22bc875edb80042515acd2172e58b4518 }


condition:
	$a0
}