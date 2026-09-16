rule Win_Trojan_Girda_1
{
strings:
	$a0 = { 02ba8000b901008d9c7c03cd132680bc4e0551750b26c6844e0500b80103cd13c3b8014332ed }


condition:
	$a0
}