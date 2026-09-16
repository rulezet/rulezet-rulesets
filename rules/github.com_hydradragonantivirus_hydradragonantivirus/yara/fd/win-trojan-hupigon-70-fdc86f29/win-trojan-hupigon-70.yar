rule Win_Trojan_Hupigon_70
{
strings:
	$a0 = { 800300000448696e74060a47524159504947454f4e0950 }


condition:
	$a0
}