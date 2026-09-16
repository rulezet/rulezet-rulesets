rule Win_Trojan_Ash_12
{
strings:
	$a0 = { 21b4408b0e3e02ba0401cd21b801438b8e3102cd21b801578b8e32028b963402cd21b43ecd21b4 }


condition:
	$a0
}