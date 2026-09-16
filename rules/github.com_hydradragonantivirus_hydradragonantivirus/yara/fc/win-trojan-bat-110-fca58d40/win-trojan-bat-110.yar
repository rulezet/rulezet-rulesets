rule Win_Trojan_BAT_110
{
strings:
	$a0 = { 6e65742073746f7020226d707373766322 }


condition:
	$a0
}