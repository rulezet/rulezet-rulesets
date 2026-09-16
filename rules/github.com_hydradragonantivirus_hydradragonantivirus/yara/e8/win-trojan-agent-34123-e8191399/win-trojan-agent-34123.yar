rule Win_Trojan_Agent_34123
{
strings:
	$a0 = { 602bfb616052680aff6e405a5ae800000000 }


condition:
	$a0
}