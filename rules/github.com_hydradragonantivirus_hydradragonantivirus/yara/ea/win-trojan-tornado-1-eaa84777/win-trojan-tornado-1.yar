rule Win_Trojan_Tornado_1
{
strings:
	$a0 = { 5657bf7034be527c2e313c03fe4681fe847d75f45f5e9dc3c9 }


condition:
	$a0
}