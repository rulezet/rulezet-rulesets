rule Win_Trojan_Awake_5
{
strings:
	$a0 = { 212ce30f9a6c1de71dfc9e2ce30f9a6e97332d203194e528e30f9a799e }


condition:
	$a0
}