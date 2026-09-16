rule Win_Trojan_Little_4
{
strings:
	$a0 = { 4eba2d01cd21b8013dba9e00cd21ba00018bd8b15ab440cd21b43ecd21b44fcd2173e3b409ba3601cd21cd20 }


condition:
	$a0
}