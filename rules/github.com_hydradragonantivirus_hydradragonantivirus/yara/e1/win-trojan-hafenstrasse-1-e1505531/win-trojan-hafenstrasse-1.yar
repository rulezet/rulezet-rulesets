rule Win_Trojan_Hafenstrasse_1
{
strings:
	$a0 = { 741e8a170ad2740743b402cd21ebf3b20db402cd21 }


condition:
	$a0
}