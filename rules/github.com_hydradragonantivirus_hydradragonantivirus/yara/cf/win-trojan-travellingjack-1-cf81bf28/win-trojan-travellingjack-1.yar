rule Win_Trojan_TravellingJack_1
{
strings:
	$a0 = { 8c1e08048cc88ec08ed8803e09000074168a160900bb }


condition:
	$a0
}