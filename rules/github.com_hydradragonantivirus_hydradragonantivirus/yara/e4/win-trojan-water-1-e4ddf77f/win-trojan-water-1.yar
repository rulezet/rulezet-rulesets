rule Win_Trojan_Water_1
{
strings:
	$a0 = { 40b96d02908bd683ea24cd21b80157 }


condition:
	$a0
}