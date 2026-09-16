rule Win_Trojan_Trivial_20
{
strings:
	$a0 = { 01c3b80043ba9e00cd21b443b001b100cd21b8013dcd2193b440b1379090ba0001cd21b43e }


condition:
	$a0
}