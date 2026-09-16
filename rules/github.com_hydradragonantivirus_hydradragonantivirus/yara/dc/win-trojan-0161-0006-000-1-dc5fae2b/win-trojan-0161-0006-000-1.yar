rule Win_Trojan__0161_0006_000_1
{
strings:
	$a0 = { 3dba9e00cd2193b440ba0001b9dc00cd21b43ecd21b44fe951ff2a2e657865005b4c697665 }


condition:
	$a0
}