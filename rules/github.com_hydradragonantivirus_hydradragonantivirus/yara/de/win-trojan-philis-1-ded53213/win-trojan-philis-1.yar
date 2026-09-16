rule Win_Trojan_Philis_1
{
strings:
	$a0 = { 8d85a4feffff8d562cb904010000e89b9dffff8b8da4feffff8d85a8feffff8b55fce8eb9dffff8b85a8feffffe83cfcffff5657e885adffff85c0758457e86badffff }


condition:
	$a0
}