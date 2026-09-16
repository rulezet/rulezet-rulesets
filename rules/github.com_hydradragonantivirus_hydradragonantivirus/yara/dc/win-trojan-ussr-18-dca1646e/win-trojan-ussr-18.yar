rule Win_Trojan_USSR_18
{
strings:
	$a0 = { 0242e8fffea3a900b90402b440e8f4fe722e2bc8752a }


condition:
	$a0
}