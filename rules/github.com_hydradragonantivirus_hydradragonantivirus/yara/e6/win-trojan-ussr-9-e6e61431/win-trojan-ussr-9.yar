rule Win_Trojan_USSR_9
{
strings:
	$a0 = { 0633c08ed8fb2e8b941000ec3403ee }


condition:
	$a0
}