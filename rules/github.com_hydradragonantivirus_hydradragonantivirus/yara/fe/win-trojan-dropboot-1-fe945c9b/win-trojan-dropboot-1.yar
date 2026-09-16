rule Win_Trojan_DropBoot_1
{
strings:
	$a0 = { b8730050cbbe700056bf9600a5a5fa5fc7059a008c4502fb1e07b80102b90900ba80000653cd13cb }


condition:
	$a0
}