rule Win_Trojan_KL_2
{
strings:
	$a0 = { 8901b177f3a433dbb90100b600cd1807f85a5b59585f5e1feb98b80102bb007ccd18c3 }


condition:
	$a0
}