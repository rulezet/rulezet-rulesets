rule Win_Trojan_Icon_4
{
strings:
	$a0 = { 2e726567777269746522686b6579 }

	$a1 = { 5c68746d6c66696c655c64656661756c7469636f6e }

	$a2 = { 5c7368656c6c33322e646c6c2c3332 }


condition:
	$a0 and $a1 and $a2
}