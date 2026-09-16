rule Win_Trojan_Merlin_3
{
strings:
	$a0 = { 4d3c4572506295eab49ac036818813777859822ead8a14847b27b863d43e5df46e26e0dec4b8d9bd }


condition:
	$a0
}