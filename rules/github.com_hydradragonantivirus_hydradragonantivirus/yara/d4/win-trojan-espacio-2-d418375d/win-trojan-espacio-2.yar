rule Win_Trojan_Espacio_2
{
strings:
	$a0 = { 416ab90114b4002ec6066e04db3c027208b0802ec6066e04008bd0b80102cd137207b80103cd13 }


condition:
	$a0
}