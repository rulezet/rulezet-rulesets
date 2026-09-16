rule Win_Trojan_Natas_10
{
strings:
	$a0 = { c645bd31f681ce1e3e81cb75d7bde9ee36bf7f5981c779af89e987d94589d946f7d80182feff4fbbcab30bff87cb79ea }


condition:
	$a0
}