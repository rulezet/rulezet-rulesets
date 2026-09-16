rule Win_Trojan_Diskjeb_1
{
strings:
	$a0 = { 5351061e9c8cc88ed8e85d00803e4903 }


condition:
	$a0
}