rule Win_Trojan_Hafenstrasse_2
{
strings:
	$a0 = { 40008ed8d1cd332e6c001ff7c507007406b44fcd2173e7 }


condition:
	$a0
}