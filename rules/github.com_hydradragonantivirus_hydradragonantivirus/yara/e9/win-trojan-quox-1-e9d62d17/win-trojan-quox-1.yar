rule Win_Trojan_Quox_1
{
strings:
	$a0 = { 82000650cb0e1f33c08ec0bb007cb80102beb0018b0c8b5402e852007205ea007c0000ebfe }


condition:
	$a0
}