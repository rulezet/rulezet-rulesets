rule Win_Trojan_MiniGRB_1
{
strings:
	$a0 = { 4eba5e01cd21731656060e0787feb99bfeb8250150cbf3a45e06061f56cb92b8023db29ecd2193 }


condition:
	$a0
}