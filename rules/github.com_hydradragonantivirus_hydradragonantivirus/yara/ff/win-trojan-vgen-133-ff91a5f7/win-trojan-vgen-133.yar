rule Win_Trojan_VGEN_133
{
strings:
	$a0 = { 01bf1c002e812d400d47474875f6280e406bc1fb530df9f8492b462b4e2c4e1496f834992e9bf675409afe6d40b2 }


condition:
	$a0
}