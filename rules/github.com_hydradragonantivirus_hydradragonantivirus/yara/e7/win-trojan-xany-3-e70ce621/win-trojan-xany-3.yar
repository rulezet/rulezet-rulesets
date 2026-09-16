rule Win_Trojan_Xany_3
{
strings:
	$a0 = { 68010e1f8bd62bd102c8b440cd21b8004233c999cd21b10358572bc18bfe2bf98bd7c605e947ab }


condition:
	$a0
}