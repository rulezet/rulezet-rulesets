rule Win_Trojan_Freedom_1
{
strings:
	$a0 = { e2f95e592e803e630900740a2ec606630900cd21ebddc3 }


condition:
	$a0
}