rule Win_Trojan_Trivial_467
{
strings:
	$a0 = { 1304cd21ba2604b90200b44ecd21b44fba2604cd21b443ba9e00b000cd21b100b44390ba9e00b001cd21b8023d }


condition:
	$a0
}