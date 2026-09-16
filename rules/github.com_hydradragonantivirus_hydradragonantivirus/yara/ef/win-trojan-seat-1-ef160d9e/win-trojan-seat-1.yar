rule Win_Trojan_Seat_1
{
strings:
	$a0 = { 13a31e609d9e2890999041bb589d9ef0682975e52b7528bb }


condition:
	$a0
}