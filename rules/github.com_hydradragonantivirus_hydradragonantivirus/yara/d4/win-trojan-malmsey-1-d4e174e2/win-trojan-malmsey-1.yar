rule Win_Trojan_Malmsey_1
{
strings:
	$a0 = { 33c0b805feebfc05fe3ac30e1fba9f01e8edff0402cd21bad901e8e3ffcce96e01cd21cfe8d9ff055b22a28f00be }


condition:
	$a0
}