rule Win_Trojan_Flue_1
{
strings:
	$a0 = { 8b37b94002b800003104f7d046464975f7c3 }


condition:
	$a0
}