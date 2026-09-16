rule Win_Trojan_Ukraine_7
{
strings:
	$a0 = { 5e81eeee04b8ac0fcd213d35357503e9b00033c08e }


condition:
	$a0
}