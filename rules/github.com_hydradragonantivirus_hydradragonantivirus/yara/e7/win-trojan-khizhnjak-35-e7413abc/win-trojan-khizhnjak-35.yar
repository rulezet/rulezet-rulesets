rule Win_Trojan_Khizhnjak_35
{
strings:
	$a0 = { 023dcd217303e9d700a3fc028d1601038b1efc02b90300 }


condition:
	$a0
}