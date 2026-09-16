rule Win_Trojan_Small_4582
{
strings:
	$a0 = { 42494e006e74646c6c2e646c6c00 }

	$a1 = { 46696e645265736f75726365410000 }


condition:
	$a0 and $a1
}