rule Win_Trojan_LordZer0_2
{
strings:
	$a0 = { 012ea3be01b440b97601ba0001cd217212b8004233c933d2cd21b440b103babd01cd21b80057 }


condition:
	$a0
}