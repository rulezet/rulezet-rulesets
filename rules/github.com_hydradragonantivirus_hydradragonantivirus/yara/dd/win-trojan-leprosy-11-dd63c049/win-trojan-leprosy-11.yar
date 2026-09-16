rule Win_Trojan_Leprosy_11
{
strings:
	$a0 = { 02900290e8040090e9ea0551b701b3388a2f90322e0401882f904381fb00097eef59c3ba00018b1ee50653e8e0ff }


condition:
	$a0
}